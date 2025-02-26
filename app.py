from flask import Flask, render_template, request, jsonify
from app.utils import monitor_container, run_trivy_scan
from app import create_app

# Initialize the Flask app
app = Flask(__name__)

# Replace these with your remote server's credentials
REMOTE_HOST = "10.0.2.9"
REMOTE_USER = "vboxuser"
REMOTE_PASS = "changeme"

# This should come after defining the routes
app = create_app()

@app.route('/', methods=['GET', 'POST'])
def monitor():
    if request.method == 'POST':
        result = monitor_container()
        return result
    # If it's a GET request, render the dashboard template
    return render_template('dashboard.html')

@app.route('/scanner', methods=['POST'])
def vulnerability_scan():
    image_name = request.json.get('image_name')
    result = run_trivy_scan(REMOTE_HOST, REMOTE_USER, REMOTE_PASS, image_name)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
