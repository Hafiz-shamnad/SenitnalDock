from flask import render_template, request, jsonify
from flask_login import LoginManager
from app.routes import auth_bp, otp_bp
from app.utils import monitor_container, run_trivy_scan
from app import create_app
from app.models.user import User
import os

# Initialize the Flask app properly
app = create_app()

# Get remote server credentials from environment variables
REMOTE_HOST = os.getenv("REMOTE_HOST", "10.0.2.9")
REMOTE_USER = os.getenv("REMOTE_USER", "vboxuser")
REMOTE_PASS = os.getenv("REMOTE_PASS", "changeme")

# Set up Flask-Login (should be done before defining routes)
login_manager = LoginManager()
login_manager.init_app(app)
# Set the login view (where unauthenticated users will be redirected)
login_manager.login_view = "main.login"  # Changed to match the blueprint structure

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def monitor():
    if request.method == 'POST':
        result = monitor_container()
        return result
    return render_template('dashboard.html')

@app.route('/scanner', methods=['POST'])
def vulnerability_scan():
    image_name = request.json.get('image_name')
    
    # Check if credentials are available
    if not all([REMOTE_HOST, REMOTE_USER, REMOTE_PASS]):
        return jsonify({"error": "Remote server credentials not configured"}), 500
        
    result = run_trivy_scan(REMOTE_HOST, REMOTE_USER, REMOTE_PASS, image_name)
    return jsonify(result)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(otp_bp, url_prefix='/otp')

if __name__ == '__main__':
    app.run(debug=False)  # Correctly set to False for production