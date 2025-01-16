from app import db

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_name = db.Column(db.String(100), nullable=False)
    cve_id = db.Column(db.String(50), nullable=False)
    mitigation = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.now())
