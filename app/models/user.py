from app.extensions import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Recommended for PostgreSQL

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Store the hashed password
    otp = db.Column(db.Integer, nullable=True)  # Store 6-digit OTP if needed

