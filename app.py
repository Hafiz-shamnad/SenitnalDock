from flask import render_template, request, jsonify
from flask_login import LoginManager
from app.routes import auth_bp, otp_bp
from app.utils import monitor_container, run_trivy_scan
from app import create_app
from app.models.user import User


# Initialize the Flask app properly
app = create_app()

# Remote server credentials
REMOTE_HOST = "10.0.2.9"
REMOTE_USER = "vboxuser"
REMOTE_PASS = "changeme"

@app.route('/', methods=['GET', 'POST'])
def monitor():
    if request.method == 'POST':
        result = monitor_container()
        return result
    return render_template('dashboard.html')

@app.route('/scanner', methods=['POST'])
def vulnerability_scan():
    image_name = request.json.get('image_name')
    result = run_trivy_scan(REMOTE_HOST, REMOTE_USER, REMOTE_PASS, image_name)
    return jsonify(result)

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # ✅ Correct Import

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(otp_bp, url_prefix='/otp')

if __name__ == '__main__':
    app.run(debug=True)
