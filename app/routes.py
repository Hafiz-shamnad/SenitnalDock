from flask import Blueprint, render_template, jsonify, request , redirect, url_for, session, flash , send_file
from app.utils import run_trivy_scan, generate_report , get_mitigation , monitor_container , get_running_containers ,fetch_logs , stop_container , restart_container ,send_email
from flask import Flask, render_template, request, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
import random
import pyotp
from flask_login import login_user
from app.models.user import User, db 
from flask_sock import Sock
import os

app = Flask(__name__, static_url_path='', static_folder='static')
main = Blueprint('main', __name__)
sock = Sock()

sock.init_app(main)

NVD_API_KEY = os.getenv("NVD_API_KEY")
login_manager = LoginManager()
login_manager.init_app(app)  # Attach it to the Flask app
login_manager.login_view = 'main.login'  # Redirect to login page if unauthorized


@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@main.route('/monitor', methods=['GET'])
def get_container_stats():
    data = monitor_container()
    return jsonify(data)

@main.route('/containers', methods=['GET'])
def list_containers():
    """API to return running containers."""
    return jsonify(get_running_containers()) 

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
    Handles the /generate-report endpoint to fetch CVE details and generate a PDF report.
    """
    # Extract CVE list from the request
    data = request.json
    cve_list = data.get('cve_list', [])

    # Check if CVE list is provided
    if not cve_list:
        return jsonify({'error': 'No CVE list provided'}), 400

    print("Received CVE List:", cve_list)  # Debugging output to verify input

    # Prepare a list to store detailed CVE information
    detailed_cves = []
    for cve in cve_list:
        try:
            # Validate that the CVE entry has the 'CVE' key
            cve_id = cve.get('cve_id')
            if not cve_id:
                print("Skipping invalid CVE entry:", cve)  # Log skipped entries
                continue

            # Fetch detailed information for the CVE
            detailed_cves.append(get_mitigation(cve_id, NVD_API_KEY))
        except Exception as e:
            print(f"Error fetching details for CVE {cve}: {e}")  # Log errors

    # Check if any CVE details were successfully fetched
    if not detailed_cves:
        return jsonify({'error': 'Failed to fetch any CVE details'}), 500

    # Generate the report PDF
    output_path = "report.pdf"
    try:
        generate_report(detailed_cves, output_path)
        return jsonify({'message': 'Report generated successfully', 'path': output_path})
    except Exception as e:
        return jsonify({'error': f"Failed to generate report: {e}"}), 500

@sock.route("/logs")
def stream_logs(ws):
    while True:
        message = ws.receive()  # ✅ WebSocket clients should send data
        if not message:
            ws.send("Error: No container specified")
            continue

        # Assuming message is the container name
        container_name = message.strip()

        fetch_logs(ws, container_name)  # Your log function
        
@main.route("/stop_container", methods=["POST"])
def stop():
    """Stop selected containers."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON or no JSON provided"}), 400

    container_ids = data.get("container_ids")  # Match frontend key
    if not container_ids or not isinstance(container_ids, list):
        return jsonify({"error": "Container IDs are required and must be a list"}), 400

    stopped_containers = []
    errors = []

    for container_id in container_ids:
        try:
            stop_container(container_id)
            stopped_containers.append(container_id)
        except Exception as e:
            errors.append(f"Failed to stop {container_id}: {str(e)}")

    if errors:
        return jsonify({"error": errors, "stopped_containers": stopped_containers}), 500

    return jsonify({"message": f"Containers {', '.join(stopped_containers)} stopped successfully"}), 200

@main.route("/restart_container", methods=["POST"])
def restart():
    """Restart selected containers."""
    data = request.get_json(silent=True)
    
    if not data:
        return jsonify({"error": "Invalid JSON or no JSON provided"}), 400

    container_ids = data.get("container_ids")  # Match frontend key
    if not container_ids or not isinstance(container_ids, list):
        return jsonify({"error": "Container IDs are required and must be a list"}), 400

    restarted_containers = []
    errors = []

    for container_id in container_ids:
        try:
            restart_container(container_id)
            restarted_containers.append(container_id)
        except Exception as e:
            errors.append(f"Failed to restart {container_id}: {str(e)}")

    response = {
        "restarted_containers": restarted_containers,
        "errors": errors
    }

    status_code = 200 if not errors else 207  # 207: Multi-Status (some succeeded, some failed)
    return jsonify(response), status_code



@main.route("/stop", methods=["GET"])
def stop_page():
    """Render the container stopping page."""
    return render_template("stop_container.html")

@main.route("/restart", methods=["GET"])
def restart_page():
    """Render the container stopping page."""
    return render_template("restart_container.html")




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

            # Send OTP via email
            send_email(
    user.email,
    "🔒 Secure Login OTP - Action Required",
    body=f"Your OTP is: {otp}. Please use it within 10 minutes.",
    html_body=f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: #2C3E50;">Your One-Time Password (OTP)</h2>
            <p>Dear {user.username},</p>
            <p>We received a login request for your account. To proceed, please use the following OTP:</p>
            <h3 style="color: #27AE60; font-size: 24px;">{otp}</h3>
            <p>This OTP is valid for <strong>10 minutes</strong>. Please do not share it with anyone.</p>
            <p>If you did not attempt to log in, please ignore this email or contact support immediately.</p>
            <hr>
            <p style="font-size: 14px; color: #7F8C8D;">Best regards,<br><strong>Team SentinalDock</strong></p>
        </body>
    </html>
    """
)


            session['username'] = username  # Store user session
            flash('OTP sent to your email. Please verify.', 'info')
            return redirect(url_for('main.verify_otp'))

        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))



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

        print(f"Stored OTP: {user.otp} (Type: {type(user.otp)}), Entered OTP: {otp} (Type: {type(otp)})")  # Debugging line

        if str(user.otp) == str(otp):  # Ensure type consistency
            load_user(user.id)  # Pass only the user ID
            user.otp = None  # Clear OTP after successful verification
            db.session.commit()
            return redirect(url_for('main.dashboard'))

        flash('Invalid OTP', 'danger')

    return render_template('verify_otp.html')




@main.route('/setup-2fa')
def setup_2fa():
    user = User.query.filter_by(username=session.get('username')).first()

    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.otp_secret)
    qr_code_url = totp.provisioning_uri(user.email, issuer_name="FlaskApp")

    return render_template('setup_2fa.html', qr_url=qr_code_url)

@main.route('/verify-totp', methods=['POST'])
def verify_totp():
    otp = request.form['otp']
    user = User.query.filter_by(username=session.get('username')).first()
    
    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(otp):
        login_user(user)
        return redirect(url_for('main.dashboard'))
    
    flash('Invalid TOTP', 'danger')
    return redirect(url_for('main.setup_2fa'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)