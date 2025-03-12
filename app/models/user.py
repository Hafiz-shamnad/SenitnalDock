from app.extensions import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Recommended for PostgreSQL

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Store the hashed password
    otp = db.Column(db.Integer, nullable=True)  # Store 6-digit OTP if needed

class CVEReport(db.Model):
    __tablename__ = 'cvereport' 
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Keep only this timestamp
    
