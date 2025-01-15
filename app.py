from flask import Flask, render_template, request, jsonify
from ssh_utils.monitor import monitor_container
from ssh_utils.scanner import scan_image

app = Flask(__name__)

# Replace these with your remote server's credentials
REMOTE_HOST = "10.0.2.9"
REMOTE_USER = "vboxuser"
REMOTE_PASS = "changeme"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/monitor', methods=['POST'])
def monitor():
    container_id = request.json.get('container_id')
    result = monitor_container(REMOTE_HOST, REMOTE_USER, REMOTE_PASS, container_id)
    return jsonify(result)

@app.route('/vulnerability_scan', methods=['POST'])
def vulnerability_scan():
    image_name = request.json.get('image_name')
    result = scan_image(REMOTE_HOST, REMOTE_USER, REMOTE_PASS, image_name)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
