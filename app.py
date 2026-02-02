from flask import Flask, render_template, request, Response, session, send_file, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from scanner import VulnerabilityScanner
from db import db, init_db, Scan, Vulnerability, User
from logger_config import get_logger, setup_flask_logging
import json
import io
from fpdf import FPDF
import csv
from datetime import datetime

logger = get_logger(__name__)

app = Flask(__name__)
setup_flask_logging(app)
app.secret_key = "secret_key_secure_123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vibescanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logger.info("Initializing VibeScanner application")

# Initialize database
db.init_app(app)
with app.app_context():
    db.create_all()
    logger.info("Database initialized")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
logger.info("Flask-Login initialized")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not user.check_password(password):
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
        
        logger.info(f"User {username} logged in successfully")
        login_user(user)
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('signup'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            logger.warning(f"Registration attempt with existing username: {username}")
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            logger.warning(f"Registration attempt with existing email: {email}")
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {username} ({email})")
        flash('Account created! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info(f"User {username} logged out")
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/scan_stream')
@login_required
def scan_stream():
    target_url = request.args.get('url')
    
    if not target_url:
        logger.warning("Scan attempted without URL")
        return Response("data: [DONE] No URL provided.\n\n", mimetype='text/event-stream')

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    logger.info(f"Starting scan for user {current_user.username} on {target_url}")
    scanner = VulnerabilityScanner(target_url)
    
    # Create a new scan record in the database (associated with current user)
    scan = Scan(target_url=target_url, status='in_progress', user_id=current_user.id)
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    logger.info(f"Scan ID: {scan_id}, URL: {target_url}, User: {current_user.username}")

    def generate():
        # Need to preserve app context for database operations
        app_context = app.app_context()
        app_context.push()
        
        vuln_count = 0
        scan_error = False
        try:
            # Iterate through the generator from scanner.py
            for update in scanner.run_scan():
                # Strip newlines from update for processing
                update_clean = update.strip()
                logger.debug(f"Stream: {update_clean[:100]}")
                
                # Check if scan failed
                if "[DONE] Scan Failed" in update_clean:
                    scan_error = True
                
                # If we find a vulnerability, save it to the database
                if "[VULN]" in update_clean:
                    try:
                        # Extract the JSON part - scanner yields "data: [VULN] {...}\n\n"
                        if "data: [VULN] " in update_clean:
                            json_str = update_clean.split("data: [VULN] ", 1)[1]
                        else:
                            json_str = update_clean.split("[VULN] ", 1)[1]
                        
                        vuln_data = json.loads(json_str)
                        
                        # Save to database immediately
                        vulnerability = Vulnerability(
                            scan_id=scan_id,
                            type=vuln_data.get('type', 'Unknown'),
                            risk=vuln_data.get('risk', 'Low'),
                            description=vuln_data.get('type', 'Vulnerability'),
                            affected_url=vuln_data.get('url', target_url),
                            payload=vuln_data.get('payload', '')
                        )
                        db.session.add(vulnerability)
                        db.session.commit()  # Commit immediately, don't wait
                        vuln_count += 1
                        logger.debug(f"Vulnerability found: {vuln_data.get('type')} on {vuln_data.get('url', 'N/A')}")
                    except json.JSONDecodeError as je:
                        logger.error(f"Failed to parse vulnerability JSON: {je}")
                    except Exception as e:
                        logger.error(f"Failed to save vulnerability: {e}", exc_info=True)
                        try:
                            db.session.rollback()
                        except:
                            pass
                
                yield update
            
            # After scan completes - NOW UPDATE STATUS
            logger.info(f"Scan {scan_id} finished. Total vulnerabilities saved: {vuln_count}, Error: {scan_error}")
            
            # Clear the session to ensure fresh data
            db.session.expunge_all()
            
            # Get fresh scan object from database
            scan_obj = Scan.query.get(scan_id)
            if scan_obj:
                # Update scan status and count
                if scan_error:
                    scan_obj.status = 'failed'
                else:
                    scan_obj.status = 'completed'
                scan_obj.total_vulnerabilities = vuln_count
                db.session.add(scan_obj)
                db.session.commit()
                
                # Verify the update with a new query
                db.session.expunge_all()
                verified_scan = Scan.query.get(scan_id)
                logger.info(f"Scan {scan_id} completed: status={verified_scan.status}, vulns={verified_scan.total_vulnerabilities}")
            else:
                logger.error(f"Scan object not found in database: {scan_id}")
            
        except Exception as e:
            logger.error(f"Scan generator failed: {e}", exc_info=True)
            try:
                scan_obj = Scan.query.get(scan_id)
                if scan_obj:
                    scan_obj.status = 'failed'
                    db.session.add(scan_obj)
                    db.session.commit()
            except Exception as db_e:
                logger.error(f"Failed to mark scan as failed: {db_e}")
        finally:
            try:
                app_context.pop()
            except:
                pass

    return Response(generate(), mimetype='text/event-stream')

@app.route('/download_pdf')
@login_required
def download_pdf():
    scan_id = request.args.get('scan_id')
    
    if not scan_id:
        logger.warning("PDF download attempted without scan ID")
        return "No scan ID provided", 400
    
    # Retrieve scan from database and verify ownership
    scan = Scan.query.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        logger.warning(f"Unauthorized PDF download attempt for scan {scan_id} by user {current_user.username}")
        return "Scan not found or unauthorized", 404
    
    logger.info(f"Generating PDF report for scan {scan_id}")
    results = [v.to_dict() for v in scan.vulnerabilities]
    
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Title Info
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt=f"Target System: {scan.target_url}", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Scan Date: {scan.scan_date.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, txt=f"Total Vulnerabilities Detected: {len(results)}", ln=True)
    pdf.ln(10)
    
    if not results:
        pdf.set_text_color(0, 128, 0) # Green
        pdf.cell(200, 10, txt="No vulnerabilities found. System appears secure.", ln=True)
    else:
        for v in results:
            # Color coding
            if v.get('risk') == 'High':
                pdf.set_text_color(220, 53, 69) # Red
            elif v.get('risk') == 'Medium':
                pdf.set_text_color(255, 193, 7) # Orange
            else:
                pdf.set_text_color(0, 0, 0) # Black

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, txt=f"[{v.get('risk', 'Info')}] {v.get('type', 'Unknown')}", ln=True)
            
            pdf.set_text_color(0, 0, 0) # Reset to black
            pdf.set_font("Arial", size=10)
            
            # Use multi_cell for long text wrapping
            pdf.multi_cell(0, 7, txt=f"URL: {v.get('affected_url', 'N/A')}")
            pdf.multi_cell(0, 7, txt=f"Payload: {v.get('payload', 'N/A')}")
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y()) # Draw separator line
            pdf.ln(5)
            
    # Output PDF
    buffer = io.BytesIO()
    try:
        pdf_bytes = pdf.output(dest='S').encode('latin-1') 
    except:
         # Fallback for newer fpdf2 versions if the above fails
        pdf_bytes = pdf.output(dest='S')
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode('latin-1')

    buffer.write(pdf_bytes)
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, download_name="scan_report.pdf", mimetype='application/pdf')

@app.route('/api/scans')
@login_required
def get_scans():
    """Get all scans for current user with optional filtering"""
    logger.debug(f"Fetching scans for user {current_user.username}")
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status_filter = request.args.get('status')
    
    query = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.scan_date.desc())
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    scans = query.paginate(page=page, per_page=per_page)
    
    # Return lightweight scan data (without full vulnerabilities list)
    scans_data = []
    for scan in scans.items:
        scans_data.append({
            'id': scan.id,
            'target_url': scan.target_url,
            'scan_date': scan.scan_date.isoformat(),
            'status': scan.status,
            'total_vulnerabilities': scan.total_vulnerabilities
        })
    
    return jsonify({
        'scans': scans_data,
        'total': scans.total,
        'pages': scans.pages,
        'current_page': page
    })

@app.route('/api/scan/<int:scan_id>')
@login_required
def get_scan_details(scan_id):
    """Get detailed scan results"""
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(scan.to_dict())

@app.route('/api/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """Delete a scan and its vulnerabilities"""
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized scan deletion attempt for scan {scan_id}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        logger.info(f"Deleting scan {scan_id} for user {current_user.username}")
        db.session.delete(scan)
        db.session.commit()
        return jsonify({'message': 'Scan deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def get_stats():
    """Get detailed statistics about user's scans"""
    logger.debug(f"Generating statistics for user {current_user.username}")
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    total_vulns = db.session.query(Vulnerability).join(Scan).filter(Scan.user_id == current_user.id).count()
    
    # Risk level breakdown
    high_risk_vulns = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user.id,
        Vulnerability.risk == 'High'
    ).count()
    medium_risk_vulns = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user.id,
        Vulnerability.risk == 'Medium'
    ).count()
    low_risk_vulns = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user.id,
        Vulnerability.risk == 'Low'
    ).count()
    
    # Vulnerability types breakdown
    vuln_types = db.session.query(
        Vulnerability.type,
        db.func.count(Vulnerability.id).label('count')
    ).join(Scan).filter(
        Scan.user_id == current_user.id
    ).group_by(Vulnerability.type).all()
    
    vuln_types_dict = {v[0]: v[1] for v in vuln_types}
    
    # Scan status breakdown
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
    failed_scans = Scan.query.filter_by(user_id=current_user.id, status='failed').count()
    in_progress_scans = Scan.query.filter_by(user_id=current_user.id, status='in_progress').count()
    
    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'in_progress_scans': in_progress_scans,
        'total_vulnerabilities': total_vulns,
        'high_risk_vulnerabilities': high_risk_vulns,
        'medium_risk_vulnerabilities': medium_risk_vulns,
        'low_risk_vulnerabilities': low_risk_vulns,
        'vulnerability_types': vuln_types_dict
    })

@app.route('/dashboard')
@login_required
def dashboard():
    """Display statistics dashboard"""
    return render_template('dashboard.html')

@app.route('/history')
@login_required
def scan_history():
    """Display scan history page"""
    return render_template('scan_history.html')

@app.route('/api/scan/<int:scan_id>/export', methods=['GET'])
@login_required
def export_scan(scan_id):
    """Export scan as JSON, CSV, or HTML"""
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized export attempt for scan {scan_id}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    export_format = request.args.get('format', 'json')
    logger.info(f"Exporting scan {scan_id} as {export_format} for user {current_user.username}")
    
    if export_format == 'json':
        return jsonify(scan.to_dict())
    
    elif export_format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Risk', 'Description', 'Affected URL', 'Payload'])
        
        for vuln in scan.vulnerabilities:
            writer.writerow([vuln.type, vuln.risk, vuln.description, vuln.affected_url, vuln.payload])
        
        buffer = io.BytesIO()
        buffer.write(output.getvalue().encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"scan_{scan_id}_report.csv",
            mimetype='text/csv'
        )
    
    elif export_format == 'html':
        html_content = f"""
        <html>
        <head>
            <title>Scan Report - {scan.target_url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .vulnerability {{ border-left: 4px solid; padding: 10px; margin: 10px 0; }}
                .high {{ border-color: #dc3545; background: #f8d7da; }}
                .medium {{ border-color: #ffc107; background: #fff3cd; }}
                .low {{ border-color: #28a745; background: #d4edda; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Vulnerability Scan Report</h1>
                <p><strong>Target:</strong> {scan.target_url}</p>
                <p><strong>Date:</strong> {scan.scan_date.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Total Vulnerabilities:</strong> {scan.total_vulnerabilities}</p>
            </div>
        """
        
        if scan.vulnerabilities:
            for vuln in scan.vulnerabilities:
                risk_class = vuln.risk.lower()
                html_content += f"""
                <div class="vulnerability {risk_class}">
                    <h3>[{vuln.risk}] {vuln.type}</h3>
                    <p><strong>URL:</strong> {vuln.affected_url}</p>
                    <p><strong>Description:</strong> {vuln.description}</p>
                    <p><strong>Payload:</strong> <code>{vuln.payload}</code></p>
                </div>
                """
        else:
            html_content += '<p style="color: green;"><strong>No vulnerabilities found!</strong></p>'
        
        html_content += '</body></html>'
        
        buffer = io.BytesIO()
        buffer.write(html_content.encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"scan_{scan_id}_report.html",
            mimetype='text/html'
        )
    
    return jsonify({'error': 'Invalid format'}), 400

@app.route('/api/debug/scans', methods=['GET'])
@login_required
def debug_scans():
    """Debug endpoint to check database state"""
    scans = Scan.query.filter_by(user_id=current_user.id).all()
    
    result = []
    for scan in scans:
        vuln_count = Vulnerability.query.filter_by(scan_id=scan.id).count()
        result.append({
            'id': scan.id,
            'url': scan.target_url,
            'status': scan.status,
            'total_vulnerabilities_stored': scan.total_vulnerabilities,
            'actual_vulns_in_db': vuln_count,
            'scan_date': scan.scan_date.isoformat()
        })
    
    return jsonify({'scans': result})

@app.route('/api/scan/<int:scan_id>/sync', methods=['POST'])
@login_required
def sync_scan(scan_id):
    """Manually sync scan data with database"""
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Count actual vulnerabilities
    vuln_count = Vulnerability.query.filter_by(scan_id=scan_id).count()
    
    # Update scan
    if scan.status == 'in_progress' and vuln_count > 0:
        scan.status = 'completed'
    
    scan.total_vulnerabilities = vuln_count
    db.session.commit()
    
    return jsonify({
        'message': 'Sync completed',
        'status': scan.status,
        'vulnerabilities': vuln_count
    })

if __name__ == '__main__':
    # Threaded=True is important for the streaming to work smoothly
    logger.info("Starting VibeScanner Flask application")
    app.run(debug=True, threaded=True)