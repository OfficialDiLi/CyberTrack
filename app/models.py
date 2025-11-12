from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app import db  # Import db from the app package

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to scan records
    scan_records = db.relationship('ScanRecord', backref='user', lazy=True)
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the provided password matches the hash."""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if the user has admin privileges."""
        return self.role == 'admin'
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanRecord(db.Model):
    __tablename__ = 'scan_record'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    input_value = db.Column(db.String(255), nullable=False)  # URL, IP, domain, file hash
    scan_type = db.Column(db.String(50), nullable=False)  # 'url', 'ip', 'domain', 'file'
    verdict = db.Column(db.String(50))  # 'BENIGN', 'MALICIOUS', 'SUSPICIOUS'
    confidence = db.Column(db.Float)  # Confidence score (0-100)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanRecord {self.input_value} - {self.verdict}>'