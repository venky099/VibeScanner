from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json
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
    
    detected_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'risk': self.risk,
            'description': self.description,
            'affected_url': self.affected_url,
            'payload': self.payload,
            'detected_date': self.detected_date.isoformat()
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.id}: {self.type} ({self.risk})>'


def init_db(app):
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully!")
