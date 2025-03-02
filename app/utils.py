import subprocess
import json
import os , re
import paramiko
import requests
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from fpdf import FPDF
from flask import Flask
from flask import Flask, jsonify 



app = Flask(__name__)


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
SSH_HOST = "10.0.2.9"
SSH_USER = "vboxuser"
SSH_KEY = "~/.ssh/docker_monitoring_key"

# Monitor Docker container stats using SSH and SSH key authentication
def monitor_container():
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))

        command = f"docker stats --no-stream --format '{{{{json .}}}}'"
        stdin, stdout, stderr = ssh.exec_command(command)

        stats_output = stdout.read().decode('utf-8')
        error_output = stderr.read().decode('utf-8')

        if error_output:
            return {"error": error_output}
        
        if stats_output:
            stats_json = [eval(line) for line in stats_output.strip().split("\n")]
            return stats_json

        return {"error": "No output from docker stats"}

    except Exception as e:
        return {"error": str(e)}

    finally:
        ssh.close()

def get_running_containers():
    """Fetch running Docker containers."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))

        command = "docker ps --format '{{json .}}'"
        stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.read().decode('utf-8')
        error_output = stderr.read().decode('utf-8')

        ssh.close()

        if error_output:
            return {"error": error_output}

        if output:
            containers = [eval(line) for line in output.strip().split("\n")]
            return [{"ID": c["ID"], "Name": c["Names"], "Image": c["Image"]} for c in containers]

        return {"error": "No running containers found"}

    except Exception as e:
        return {"error": str(e)}
    
def clean_logs(text):
    """Remove ANSI escape codes and terminal sequences like cursor position requests."""
    ansi_escape = re.compile(r'\x1B\[[0-9;]*[mK]|\x1B\[\?25[lh]|\x1B\[[0-9]*n|\r')
    return ansi_escape.sub('', text)

def fetch_logs(ws, container_name):
    """Fetch Docker logs via SSH and stream them over WebSocket."""
    try:
        print(f"🔍 Connecting to SSH: {SSH_HOST} as {SSH_USER}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))

        json_data = container_name
        container_id = json.loads(json_data)["container"]
        command = f"docker logs -t --tail 50 --details {container_id}"
        
        stdin, stdout, stderr = ssh.exec_command(command)

        # ✅ Use `ws.connected` instead of `ws.closed`
        for line in iter(stdout.readline, ""):
            if not ws.connected:  # Flask-SocketIO uses `connected`
                break
            log_line = line.strip()
            ws.send(clean_logs(log_line))
        ssh.close()

    except paramiko.SSHException as e:
        print(error_msg)
        ws.send(error_msg)

    except Exception as e:
        print(error_msg)
        ws.send(error_msg)
            
# Define function to stop a container
def stop_container(container_id):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))

        command = f"docker stop {container_id}"
        ssh.exec_command(command)
        ssh.close()

        return jsonify({"message": f"Container {container_id} stopped successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Define function to restart a container
def restart_container(container_id):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))

        command = f"docker restart {container_id}"
        ssh.exec_command(command)
        ssh.close()

        return jsonify({"message": f"Container {container_id} restarted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500