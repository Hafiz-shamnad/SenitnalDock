from flask import Blueprint, Flask, render_template, jsonify, request, redirect, url_for, session, flash, send_file, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sock import Sock
import os
import random
from datetime import datetime
from functools import wraps
from pathlib import Path

from app.models.user import User, db, CVEReport
from app.utils import (
    run_trivy_scan, generate_report, get_mitigation, 
    monitor_container, get_running_containers, fetch_logs, 
    stop_container, restart_container, send_email, backup_container
)

# Initialize Flask app
app = Flask(__name__, static_url_path='', static_folder='static')
main = Blueprint('main', __name__)
sock = Sock()
sock.init_app(main)

# Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY")
REPORT_DIR = Path("static/reports")
REPORT_DIR.mkdir(exist_ok=True)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def handle_container_action(action_func, container_ids):
    """Generic handler for container operations."""
    if not container_ids or not isinstance(container_ids, list):
        return jsonify({"error": "Container IDs are required and must be a list"}), 400
        
    processed = []
    errors = []
    
    for container_id in container_ids:
        try:
            action_func(container_id)
            processed.append(container_id)
        except Exception as e:
            errors.append(f"Failed to process {container_id}: {str(e)}")
            
    return processed, errors

# Basic routes
@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Container monitoring and management routes
@main.route('/monitor', methods=['GET'])
def get_container_stats():
    return jsonify(monitor_container())

@main.route('/containers', methods=['GET'])
def list_containers():
    """API to return running containers."""
    return jsonify(get_running_containers()) 

@sock.route("/logs")
def stream_logs(ws):
    while True:
        message = ws.receive()
        if not message:
            ws.send("Error: No container specified")
            continue

        container_name = message.strip()
        fetch_logs(ws, container_name)

@main.route("/stop_container", methods=["POST"])
def stop():
    """Stop selected containers."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON or no JSON provided"}), 400

    stopped_containers, errors = handle_container_action(
        stop_container, 
        data.get("container_ids", [])
    )

    if errors:
        return jsonify({"error": errors, "stopped_containers": stopped_containers}), 500

    return jsonify({"message": f"Containers {', '.join(stopped_containers)} stopped successfully"}), 200

@main.route("/restart_container", methods=["POST"])
def restart():
    """Restart selected containers."""
    data = request.get_json(silent=True)
    
    if not data:
        return jsonify({"error": "Invalid JSON or no JSON provided"}), 400

    restarted_containers, errors = handle_container_action(
        restart_container,
        data.get("container_ids", [])
    )

    response = {
        "restarted_containers": restarted_containers,
        "errors": errors
    }

    status_code = 200 if not errors else 207  # 207: Multi-Status
    return jsonify(response), status_code

@main.route("/stop", methods=["GET"])
def stop_page():
    """Render the container stopping page."""
    return render_template("stop_container.html")

@main.route("/restart", methods=["GET"])
def restart_page():
    """Render the container restart page."""
    return render_template("restart_container.html")

@main.route('/backup', methods=['GET', 'POST'])
def do_backup_container():
    if request.method == 'POST':
        backup_container()
    return render_template('backup.html')

# Security scanning and reporting routes
@main.route('/scan', methods=['POST'])
def scan_image():
    data = request.json
    image_name = data.get('image_name')

    if not image_name:
        return jsonify({'error': 'Image name is required'}), 400

    try:
        scan_results = run_trivy_scan(image_name)
        return jsonify(scan_results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/generate-report', methods=['POST'])
def generate_report_route():
    """
    Handles the /generate-report endpoint to fetch CVE details, generate a PDF report, 
    and store the report details in the database with a timestamped filename.
    """
    try:
        # Extract CVE list from the request
        data = request.json
        cve_list = data.get('cve_list', [])

        if not cve_list:
            return jsonify({'error': 'No CVE list provided'}), 400

        # Fetch detailed CVE information
        detailed_cves = []
        for cve in cve_list:
            cve_id = cve.get('cve_id')
            if not cve_id:
                continue

            try:
                detailed_cves.append(get_mitigation(cve_id, NVD_API_KEY))
            except Exception as e:
                print(f"Error fetching details for CVE {cve_id}: {e}")

        if not detailed_cves:
            return jsonify({'error': 'Failed to fetch any CVE details'}), 500

        # Generate a unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cve_report_{timestamp}.pdf"
        output_path = REPORT_DIR / filename

        # Generate the report
        generate_report(detailed_cves, str(output_path))

        # Store the report in the database
        new_report = CVEReport(filename=filename, file_path=str(output_path), created_at=datetime.now())
        db.session.add(new_report)
        db.session.commit()

        return jsonify({
            'message': 'Report generated successfully',
            'report_path': str(output_path)
        }), 200

    except Exception as e:
        return jsonify({'error': f"Internal Server Error: {str(e)}"}), 500

@main.route('/reports')
def reports():
    reports = CVEReport.query.order_by(CVEReport.created_at.desc()).all()
    return render_template('reports.html', reports=reports)

@main.route('/download/<int:report_id>')
def download_report(report_id):
    # Fetch the report from the database
    report = CVEReport.query.get_or_404(report_id)
    
    # Ensure the file path is correct
    file_path = os.path.join("/home/hafiz/SenitnalDock/static/reports", os.path.basename(report.file_path))

    # Check if the file exists before sending it
    if not os.path.exists(file_path):
        abort(404, description="Report not found")

    return send_file(file_path, as_attachment=True)

# User authentication and management routes
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists', 'danger')
            return redirect(url_for('main.register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Generate a random 6-digit OTP
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            db.session.commit()
            
            # Send OTP via email with SentinalDock theming
            email_html = f"""
            <html>
                <body style="font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; background-color: #f9f9f9; padding: 20px; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: #fff; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <div style="border-left: 4px solid #0078d4; padding-left: 15px; margin-bottom: 20px;">
                            <h2 style="color: #0078d4; margin: 0;">Security Authentication Required</h2>
                        </div>
                        <p>Hello {user.username},</p>
                        <p>A login attempt was detected for your SentinalDock account. To verify your identity, please use the following one-time password:</p>
                        <div style="background-color: #f0f8ff; border-radius: 5px; padding: 15px; text-align: center; margin: 20px 0;">
                            <h3 style="color: #0078d4; font-size: 28px; letter-spacing: 5px; margin: 0;">{otp}</h3>
                        </div>
                        <p>This code will expire in <strong>5 minutes</strong>.</p>
                        <p>If you did not attempt to log in, please secure your account immediately and contact our security team.</p>
                        <hr style="border: none; border-top: 1px solid #eaeaea; margin: 25px 0;">
                        <p style="font-size: 14px; color: #666; text-align: center;">
                            &copy; 2025 SentinalDock - Container Security Management System<br>
                            <span style="color: #0078d4;">Protecting your containers. Securing your infrastructure.</span>
                        </p>
                    </div>
                </body>
            </html>
            """
            
            send_email(
                user.email,
                "🔒 SentinalDock Security Verification Code",
                body=f"Your SentinalDock verification code is: {otp}. Valid for 5 minutes.",
                html_body=email_html
            )
            
            session['username'] = username  # Store user session
            flash('Security code sent to your email. Please verify to continue.', 'info')
            return redirect(url_for('main.verify_otp'))
            
        flash('Invalid credentials detected. Please try again.', 'danger')
    return render_template('login.html')

@main.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    username = session.get('username')
    if not username:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("main.login"))

    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.login"))

    if request.method == 'POST':
        otp = request.form['otp']

        if user.otp is None:
            flash("No OTP found. Request a new one.", "danger")
            return redirect(url_for("main.login"))

        if str(user.otp) == str(otp):  # Ensure type consistency
            load_user(user.id)  # Use login_user instead of load_user
            user.otp = None  # Clear OTP after successful verification
            db.session.commit()
            return redirect(url_for('main.dashboard'))

        flash('Invalid OTP', 'danger')

    return render_template('verify_otp.html')

@main.route('/logout')
def logout():
    return redirect(url_for('main.login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)