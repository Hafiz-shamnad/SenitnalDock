import subprocess
import json
import os , re
import paramiko
import requests
from flask import Flask , request
from flask import Flask, jsonify 
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from textwrap import fill
import datetime



app = Flask(__name__)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves"
NVD_API_KEY = os.getenv("NVD_API_KEY")

def ssh_command(command):
    """Executes an SSH command on the remote server."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()

        ssh.close()
        return output if output else None, error if error else None

    except Exception as e:
        return None, str(e)

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
    """Generates a professional CVE report in PDF with proper word wrapping and page handling."""

    try:
        # Create custom colors for sentinel/dark theme
        sentinel_dark = colors.Color(0.10, 0.12, 0.16)  # Dark blue-gray background
        sentinel_header = colors.Color(0.15, 0.18, 0.24)  # Slightly lighter for headers
        sentinel_text = colors.Color(0.90, 0.90, 0.95)  # Light gray text
        sentinel_critical = colors.Color(0.90, 0.22, 0.27)  # Red for critical items
        sentinel_high = colors.Color(0.95, 0.55, 0.20)  # Orange for high risk
        
        # Document setup
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        
        # Custom styles
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='TitleCustom',
            parent=styles['Title'],
            textColor=sentinel_dark
        ))
        
        styles.add(ParagraphStyle(
            name='HeadingCustom',
            parent=styles['Heading2'],
            textColor=sentinel_text
        ))
        
        styles.add(ParagraphStyle(
            name='NormalCustom',
            parent=styles['Normal'],
            textColor=sentinel_text
        ))
        
        # Get current time
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Elements list
        elements = []
        
        # Title with generation info
        title = Paragraph(f"<b>CVE Security Report</b>", styles["TitleCustom"])
        elements.append(title)
        
        # Add generation metadata
        metadata = Paragraph(f"Generated: {current_time}", styles["NormalCustom"])
        elements.append(metadata)
        elements.append(Spacer(1, 20))
        
        for cve in cve_details:
            # Determine risk level for color coding
            score = 0
            try:
                score = float(cve["Impact Score"])
            except (ValueError, TypeError):
                pass
                
            # Format text properly
            wrapped_description = fill(cve["Description"], width=80)
            wrapped_impact = fill(str(cve["Impact Score"]), width=80)
            formatted_references = "\n".join(fill(link, width=80) for link in cve["References"].split("\n"))
            
            # Data for the table
            table_data = [
                [Paragraph(f"<b>CVE:</b> {cve['CVE']}", styles["HeadingCustom"])],
                [Paragraph(f"<b>Description:</b> {wrapped_description}", styles["NormalCustom"])],
                [Paragraph(f"<b>Impact Score:</b> {wrapped_impact}", styles["NormalCustom"])],
                [Paragraph("<b>References:</b>", styles["NormalCustom"])],
                [Paragraph(formatted_references, styles["NormalCustom"])]
            ]
            
            # Determine background color based on risk
            risk_color = sentinel_dark
            if score >= 7.0:
                risk_color = sentinel_critical
            elif score >= 4.0:
                risk_color = sentinel_high
            
            # Table setup with sentinel theme
            table = Table(table_data, colWidths=[500])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), sentinel_header),  # Header row
                ('TEXTCOLOR', (0, 0), (-1, 0), sentinel_text),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), sentinel_dark),  # Content rows
                ('TEXTCOLOR', (0, 1), (-1, -1), sentinel_text),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ]))
            
            # For high risk items, add a special row at the top
            if score >= 7.0:
                risk_text = "HIGH RISK" if score >= 7.0 and score < 9.0 else "CRITICAL RISK"
                risk_data = [[Paragraph(f"<b>{risk_text}</b>", styles["HeadingCustom"])]]
                risk_table = Table(risk_data, colWidths=[500])
                risk_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, 0), risk_color),
                    ('TEXTCOLOR', (0, 0), (0, 0), sentinel_text),
                    ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (0, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (0, 0), 8),
                    ('TOPPADDING', (0, 0), (0, 0), 8),
                ]))
                elements.append(risk_table)
                
            elements.append(table)
            elements.append(Spacer(1, 30))  # Space between entries
            
        doc.build(elements)
        print("PDF report generated successfully.")
        
    except Exception as e:
        print(f"Error generating PDF: {e}")
        raise

        
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


def send_email(user_email, subject, body, html_body=None):
    try:
        # Set up the email
        msg = MIMEMultipart()
        msg['From'] = Config.MAIL_DEFAULT_SENDER
        msg['To'] = user_email
        msg['Subject'] = subject

        # Attach plain text (fallback for clients that don't support HTML)
        msg.attach(MIMEText(body, 'plain'))

        # Attach HTML version if provided
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))

        # Connect to Gmail's SMTP server
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(Config.MAIL_DEFAULT_SENDER, Config.MAIL_PASSWORD)

        # Send the email
        server.sendmail(Config.MAIL_DEFAULT_SENDER, user_email, msg.as_string())
        server.quit()

        print("Email sent successfully!")
    except Exception as e:
        print(f"Error: {e}")

# Define backup directory
BACKUP_DIR = "/home/vboxuser/backup/docker"

def backup_container():
    """Creates a backup of selected Docker containers on the remote server."""
    try:
        # Get container IDs from request
        data = request.get_json()
        container_ids = data.get("container_ids", [])

        if not container_ids:
            return jsonify({"error": "No containers selected for backup"}), 400

        backup_results = []

        for container_id in container_ids:
            # Commit the container to a new image
            backup_image_name = f"backup_{container_id}"
            _, error = ssh_command(f"docker commit -p {container_id} {backup_image_name}")
            if error:
                backup_results.append({"container_id": container_id, "error": error})
                continue

            # Save the image as a tar file
            backup_file = f"{BACKUP_DIR}/{backup_image_name}.tar"
            _, error = ssh_command(f"docker save -o {backup_file} {backup_image_name}")
            print(f"docker save -o {backup_file} {backup_image_name}")
            if error:
                backup_results.append({"container_id": container_id, "error": error})
                continue

            # Append success result
            backup_results.append({"container_id": container_id, "backup_file": backup_file})

        return jsonify({"success": True, "backups": backup_results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500