import json
from ssh_utils.ssh_client import SSHClient
import re


def scan_image(host, username, password, image_name):
    client = SSHClient(host, username, password)
    if not client.connect():
        return {"success": False, "error": "Failed to connect to server."}

    # Run Trivy scan with JSON output
    command = f"trivy image --format json {image_name}"
    try:
        output, error = client.execute(command)
        client.close()
        if error:
            return {"success": False, "error": error}

        # Log the raw output to debug
        print("Raw Output:", output)

        # Parse the JSON output from Trivy
        try:
            result_json = json.loads(output)
            os_info = "Unknown OS"
            total_vulnerabilities = {
                "UNKNOWN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0
            }

            # Extract OS information from Trivy output, with fallback to "Unknown OS"
            if 'Meta' in result_json and 'OS' in result_json['Meta']:
                os_info = f"{result_json['Meta']['OS']['Family']} ({result_json['Meta']['OS']['Version']})"

            # Extract vulnerability details if any exist
            vulnerabilities = result_json[0].get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                severity = vuln.get('Severity', 'UNKNOWN')
                if severity in total_vulnerabilities:
                    total_vulnerabilities[severity] += 1

            # Format the vulnerability summary
            summary = f"Total: {sum(total_vulnerabilities.values())} (UNKNOWN: {total_vulnerabilities['UNKNOWN']}, LOW: {total_vulnerabilities['LOW']}, MEDIUM: {total_vulnerabilities['MEDIUM']}, HIGH: {total_vulnerabilities['HIGH']}, CRITICAL: {total_vulnerabilities['CRITICAL']})"

            return {
                "success": True,
                "os": os_info,
                "summary": summary,
                "scan_result": output  # Full raw Trivy output
            }
        except json.JSONDecodeError:
            return {"success": False, "error": "Error parsing Trivy output."}
    except Exception as e:
        client.close()
        return {"success": False, "error": f"An error occurred: {str(e)}"}
