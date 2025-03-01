from flask import Blueprint, render_template, jsonify, request
from app.utils import run_trivy_scan, generate_report , get_mitigation , monitor_container , get_running_containers ,fetch_logs
from flask import Flask, render_template, request, jsonify
from flask_sock import Sock
import os

app = Flask(__name__, static_url_path='', static_folder='static')
main = Blueprint('main', __name__)
sock = Sock()

sock.init_app(main)

NVD_API_KEY = os.getenv("NVD_API_KEY")

@main.route('/')
def home():
    return render_template('dashboard.html')

@main.route('/monitor', methods=['GET'])
def get_container_stats():
    data = monitor_container()
    return jsonify(data)

@main.route('/containers', methods=['GET'])
def list_containers():
    """API to return running containers."""
    return jsonify(get_running_containers()) 
    
# @main.route('/logs', methods=['GET'])
# def get_container_logs():
#     container_name = request.args.get("container")
    
#     if not container_name:
#         return jsonify({"error": "Container name is required"}), 400

#     try:
#         fetch_logs(container_name)  # Starts the logging thread
#         return jsonify({"message": f"Started streaming logs for {container_name}"}), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500  # Ensure start_logs returns a response

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)