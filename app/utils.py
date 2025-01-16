import subprocess
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from fpdf import FPDF

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



def generate_report(cve_list):
    """
    Generate a PDF report with CVE details.
    Args:
        cve_list (list): List of CVE details where each item is a dictionary.
        Example: [{'cve_id': 'CVE-1234-5678', 'description': 'Some issue', 'mitigation': 'Apply patch'}]
    Returns:
        str: Path to the generated PDF file.
    """
    pdf_path = "cve_report.pdf"

    try:
        # Create a canvas for the PDF
        c = canvas.Canvas(pdf_path, pagesize=letter)
        width, height = letter

        # Add a title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "CVE Report")
        c.setFont("Helvetica", 12)

        # Add each CVE to the report
        y_position = height - 100
        for cve in cve_list:
            if y_position < 100:  # Create a new page if space is insufficient
                c.showPage()
                c.setFont("Helvetica", 12)
                y_position = height - 50

            cve_id = cve.get("cve_id", "N/A")
            description = cve.get("description", "No description available")
            mitigation = cve.get("mitigation", "No mitigation provided")

            c.drawString(50, y_position, f"CVE ID: {cve_id}")
            y_position -= 20
            c.drawString(50, y_position, f"Description: {description}")
            y_position -= 20
            c.drawString(50, y_position, f"Mitigation: {mitigation}")
            y_position -= 40

        # Save the PDF
        c.save()
        return pdf_path
    except Exception as e:
        raise Exception(f"Error generating PDF: {str(e)}")

