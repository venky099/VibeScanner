from flask import Flask, render_template, request, Response, session, send_file, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from scanner import VulnerabilityScanner
from db import db, init_db, Scan, Vulnerability, User
from logger_config import get_logger, setup_flask_logging
import json
import io
from fpdf import FPDF
import csv
import html
from datetime import datetime
import ipaddress
import os
import secrets
import socket
from urllib.parse import urlparse

logger = get_logger(__name__)


def get_bool_env(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_bool_arg(value, default=True):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_target_url(raw_url):
    target_url = (raw_url or "").strip()
    if not target_url:
        return None, "No URL provided."

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    parsed = urlparse(target_url)
    if parsed.scheme not in {'http', 'https'}:
        return None, "Only http:// and https:// targets are allowed."

    if not parsed.hostname:
        return None, "The target URL is invalid."

    if parsed.username or parsed.password:
        return None, "URLs with embedded credentials are not allowed."

    return target_url, None


def resolve_target_ips(hostname, port):
    try:
        ipaddress.ip_address(hostname)
        return {hostname}
    except ValueError:
        pass

    resolved_ips = set()
    addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    for entry in addrinfo:
        resolved_ips.add(entry[4][0])
    return resolved_ips


def validate_scan_target(target_url):
    normalized_url, error = normalize_target_url(target_url)
    if error:
        return None, error

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    if hostname.lower() == "localhost" or hostname.lower().endswith(".local"):
        return None, "Scanning localhost or local-only hostnames is not allowed."

    try:
        resolved_ips = resolve_target_ips(hostname, port)
    except socket.gaierror:
        return None, "The target hostname could not be resolved."
    except OSError:
        return None, "The target hostname could not be validated."

    if not resolved_ips:
        return None, "The target hostname did not resolve to a routable address."

    for resolved_ip in resolved_ips:
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not ip_obj.is_global:
            return None, "Scanning private, loopback, link-local, or otherwise non-public IP ranges is not allowed."

    return normalized_url, None

app = Flask(__name__)
setup_flask_logging(app)
app.config['SECRET_KEY'] = os.environ.get('VIBESCANNER_SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vibescanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = app.config['SECRET_KEY']

if 'VIBESCANNER_SECRET_KEY' not in os.environ:
    logger.warning("VIBESCANNER_SECRET_KEY is not set. Using an ephemeral development secret key.")

logger.info("Initializing VibeScanner application")

# Initialize database
db.init_app(app)
init_db(app)
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


def format_evidence_lines(evidence):
    if evidence is None:
        return []

    if isinstance(evidence, dict):
        lines = []
        for key, value in evidence.items():
            if isinstance(value, (dict, list)):
                rendered_value = json.dumps(value)
            else:
                rendered_value = str(value)
            lines.append(f"{key.replace('_', ' ').title()}: {rendered_value}")
        return lines

    if isinstance(evidence, list):
        return [json.dumps(item) if not isinstance(item, str) else item for item in evidence]

    return [str(evidence)]


def format_evidence_html(evidence):
    lines = format_evidence_lines(evidence)
    if not lines:
        return ""

    escaped_lines = "<br>".join(html.escape(line) for line in lines)
    return f"<p><strong>Evidence:</strong><br>{escaped_lines}</p>"

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
    include_passive_checks = parse_bool_arg(request.args.get('include_passive_checks'), True)
    
    target_url, validation_error = validate_scan_target(target_url)
    if validation_error:
        logger.warning(f"Rejected scan target: {validation_error}")
        return Response(f"data: [DONE] {validation_error}\n\n", mimetype='text/event-stream')
    
    logger.info(
        f"Starting scan for user {current_user.username} on {target_url} "
        f"(include_passive_checks={include_passive_checks})"
    )
    scanner = VulnerabilityScanner(target_url, include_passive_checks=include_passive_checks)
    
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
            yield f"data: [SCAN] {json.dumps({'scan_id': scan_id})}\n\n"

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
                            description=vuln_data.get('description', vuln_data.get('type', 'Vulnerability')),
                            affected_url=vuln_data.get('url', target_url),
                            payload=vuln_data.get('payload', ''),
                            confidence=vuln_data.get('confidence'),
                            detection_method=vuln_data.get('detection_method'),
                            evidence=json.dumps(vuln_data.get('evidence')) if vuln_data.get('evidence') is not None else None
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
            if v.get('risk') == 'Critical':
                pdf.set_text_color(255, 0, 85) # Bright red
            elif v.get('risk') == 'High':
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
            if v.get('confidence'):
                pdf.multi_cell(0, 7, txt=f"Confidence: {v.get('confidence')}")
            if v.get('detection_method'):
                pdf.multi_cell(0, 7, txt=f"Detection: {v.get('detection_method')}")
            for evidence_line in format_evidence_lines(v.get('evidence')):
                pdf.multi_cell(0, 7, txt=f"Evidence: {evidence_line}")
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
        writer.writerow(['Type', 'Risk', 'Description', 'Affected URL', 'Payload', 'Confidence', 'Detection Method', 'Evidence'])
        
        for vuln in scan.vulnerabilities:
            writer.writerow([
                vuln.type,
                vuln.risk,
                vuln.description,
                vuln.affected_url,
                vuln.payload,
                vuln.confidence,
                vuln.detection_method,
                vuln.evidence or ''
            ])
        
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
                evidence_html = format_evidence_html(vuln.to_dict().get('evidence'))
                html_content += f"""
                <div class="vulnerability {risk_class}">
                    <h3>[{vuln.risk}] {vuln.type}</h3>
                    <p><strong>URL:</strong> {html.escape(vuln.affected_url or 'N/A')}</p>
                    <p><strong>Description:</strong> {html.escape(vuln.description or '')}</p>
                    <p><strong>Payload:</strong> <code>{html.escape(vuln.payload or 'N/A')}</code></p>
                    <p><strong>Confidence:</strong> {html.escape(vuln.confidence or 'N/A')}</p>
                    <p><strong>Detection Method:</strong> {html.escape(vuln.detection_method or 'N/A')}</p>
                    {evidence_html}
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

if __name__ == '__main__':
    # Threaded=True is important for the streaming to work smoothly
    logger.info("Starting VibeScanner Flask application")
    app.run(debug=get_bool_env('FLASK_DEBUG', False), threaded=True)
