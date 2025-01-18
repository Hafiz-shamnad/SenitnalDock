import subprocess
import json
import os
import threading
import requests
import psutil
import docker
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from fpdf import FPDF
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves"
NVD_API_KEY = os.getenv("NVD_API_KEY")

def run_trivy_scan(image_name):
    """
    Runs a Trivy scan on the specified Docker image.
    Args:
        image_name (str): The name of the Docker image to scan.
    Returns:
        list: A list of CVEs with their details.
    """
    try:
        # Run Trivy and capture the output
        result = subprocess.run(
            ['trivy', 'image', '--quiet', '--format', 'json', image_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            raise Exception(result.stderr)

        # Parse the JSON output
        scan_results = json.loads(result.stdout)
        cve_list = []

        for vuln in scan_results.get('Results', []):
            for vulnerability in vuln.get('Vulnerabilities', []):
                cve = {
                    'cve_id': vulnerability.get('VulnerabilityID', 'N/A'),
                    'description': vulnerability.get('Description', 'N/A'),
                    'mitigation': vulnerability.get('Fix', 'No fix available')
                }
                cve_list.append(cve)

        return cve_list
    except Exception as e:
        raise Exception(f"Error running Trivy: {str(e)}")




def get_mitigation(cve_id, api_key):
    """Fetches details for a specific CVE ID from the NVD API."""
    url = f"{NVD_API_URL}/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key}

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # Extract CVE details
        vulnerability = data["vulnerabilities"][0]["cve"]
        descriptions = vulnerability.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available.")
        metrics = vulnerability.get("metrics", {}).get("cvssMetricV31", [{}])[0]
        impact_score = metrics.get("cvssData", {}).get("baseScore", "Not Available")
        references = vulnerability.get("references", [])

        # Format references into a single string
        references_str = "\n".join(ref["url"] for ref in references)

        return {
            "CVE": vulnerability["id"],
            "Description": description,
            "Impact Score": impact_score,
            "References": references_str,
        }
    except Exception as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")
        return {
            "CVE": cve_id,
            "Description": "Error fetching data",
            "Impact Score": "Not Available",
            "References": "None",
        }

def generate_report(cve_details, output_path):
    """Generates a PDF report with CVE details."""
    try:
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter

        c.setFont("Helvetica-Bold", 16)
        c.drawString(30, height - 50, "CVE Report")

        y_position = height - 100
        c.setFont("Helvetica", 12)

        for cve in cve_details:
            if y_position < 100:
                c.showPage()
                y_position = height - 50
                c.setFont("Helvetica", 12)

            c.drawString(30, y_position, f"CVE: {cve['CVE']}")
            y_position -= 15
            c.drawString(30, y_position, f"Description: {cve['Description']}")
            y_position -= 30
            c.drawString(30, y_position, f"Impact Score: {cve['Impact Score']}")
            y_position -= 15
            c.drawString(30, y_position, "References:")
            y_position -= 15
            for line in cve['References'].split("\n"):
                c.drawString(50, y_position, line)
                y_position -= 15
            y_position -= 20

        c.save()
    except Exception as e:
        print(f"Error generating PDF: {e}")
        
# --- System and Container Monitoring ---
def get_system_stats():
    return {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent
    }


DOCKER_REMOTE_URL = 'http://10.0.2.9:2375'

def get_container_stats():
    try:
        response = requests.get(f'{DOCKER_REMOTE_URL}/containers/json')
        containers = response.json()
        stats = []
        for container in containers:
            container_id = container['Id']
            container_name = container['Names'][0]
            stats_response = requests.get(f'{DOCKER_REMOTE_URL}/containers/{container_id}/stats?stream=false')
            stats_data = stats_response.json()
            stats.append({
                'id': container_id,
                'name': container_name,
                'cpu': stats_data['cpu_stats']['cpu_usage']['total_usage'],
                'memory': stats_data['memory_stats']['usage'],
                'status': container['State']
            })
        return stats
    except Exception as e:
        print(f"Error fetching Docker stats: {e}")
        return []



@socketio.on('connect')
def handle_connect():
    def emit_metrics():
        while True:
            stats = get_container_stats()
            socketio.emit('update_metrics', stats)
            time.sleep(5)  # Emit every 5 seconds

    threading.Thread(target=emit_metrics, daemon=True).start()

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected.")



