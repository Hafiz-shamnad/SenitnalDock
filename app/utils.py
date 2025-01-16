import subprocess
import json
from fpdf import FPDF

def run_trivy_scan(image_name):
    try:
        result = subprocess.run(['trivy', 'image', '--format', 'json', image_name],
                                capture_output=True, text=True)
        return json.loads(result.stdout)
    except Exception as e:
        raise RuntimeError(f"Trivy scan failed: {str(e)}")

def generate_report(cve_list):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', size=12)
    pdf.cell(200, 10, txt="CVE Report", ln=True, align='C')

    for cve, mitigation in cve_list.items():
        pdf.cell(0, 10, txt=f"CVE: {cve} - Mitigation: {mitigation}", ln=True)

    pdf_path = "cve_report.pdf"
    pdf.output(pdf_path)
    return pdf_path
