from flask import Blueprint, render_template, jsonify, request
from app.utils import run_trivy_scan, generate_report

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('dashboard.html')

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
    data = request.json
    cve_list = data.get('cve_list', {})

    try:
        pdf_path = generate_report(cve_list)
        return jsonify({'message': 'Report generated', 'pdf': pdf_path})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
