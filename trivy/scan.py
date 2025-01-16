import subprocess
import json

def run_trivy_scan(image_name):
    result = subprocess.run(['trivy', 'image', '--format', 'json', image_name],
                            capture_output=True, text=True)
    return json.loads(result.stdout)
