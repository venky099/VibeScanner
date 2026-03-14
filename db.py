from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json
from sqlalchemy import inspect, text
from logger_config import get_logger

logger = get_logger(__name__)

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """Represents a user account"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to scans
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
        logger.debug(f"Password hash set for user {self.username}")
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_date': self.created_date.isoformat()
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    """Represents a vulnerability scan"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    target_url = db.Column(db.String(500), nullable=False, index=True)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default='completed')  # completed, in_progress, failed
    total_vulnerabilities = db.Column(db.Integer, default=0)
    
    # Relationship to vulnerabilities
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target_url': self.target_url,
            'scan_date': self.scan_date.isoformat(),
            'status': self.status,
            'total_vulnerabilities': self.total_vulnerabilities,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target_url}>'


class Vulnerability(db.Model):
    """Represents a detected vulnerability"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    type = db.Column(db.String(100), nullable=False)  # XSS, SQL Injection, etc.
    risk = db.Column(db.String(20), nullable=False)  # High, Medium, Low
    description = db.Column(db.Text)
    affected_url = db.Column(db.String(500))
    payload = db.Column(db.Text)  # The actual payload used
    confidence = db.Column(db.String(20))
    detection_method = db.Column(db.String(50))
    evidence = db.Column(db.Text)
    
    detected_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        parsed_evidence = None
        if self.evidence:
            try:
                parsed_evidence = json.loads(self.evidence)
            except (TypeError, json.JSONDecodeError):
                parsed_evidence = self.evidence

        return {
            'id': self.id,
            'type': self.type,
            'risk': self.risk,
            'description': self.description,
            'affected_url': self.affected_url,
            'payload': self.payload,
            'confidence': self.confidence,
            'detection_method': self.detection_method,
            'evidence': parsed_evidence,
            'detected_date': self.detected_date.isoformat()
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.id}: {self.type} ({self.risk})>'


def init_db(app):
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)
        existing_columns = {column['name'] for column in inspector.get_columns('vulnerabilities')}
        schema_updates = []

        if 'confidence' not in existing_columns:
            schema_updates.append("ALTER TABLE vulnerabilities ADD COLUMN confidence VARCHAR(20)")
        if 'detection_method' not in existing_columns:
            schema_updates.append("ALTER TABLE vulnerabilities ADD COLUMN detection_method VARCHAR(50)")
        if 'evidence' not in existing_columns:
            schema_updates.append("ALTER TABLE vulnerabilities ADD COLUMN evidence TEXT")

        for statement in schema_updates:
            db.session.execute(text(statement))

        if schema_updates:
            db.session.commit()
            logger.info("Applied vulnerability table schema updates: confidence, detection_method, evidence")

        logger.info("Database tables created successfully!")
