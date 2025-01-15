from ssh_utils.ssh_client import SSHClient

def scan_image(host, username, password, image_name):
    client = SSHClient(host, username, password)
    if not client.connect():
        return {"success": False, "error": "Failed to connect to server."}

    # Simulate scanning (you can integrate a real scanner like Trivy)
    command = f"echo 'Scanning image: {image_name}'"
    try:
        output, error = client.execute(command)
        client.close()
        if error:
            return {"success": False, "error": error}
        return {"success": True, "scan_result": output}
    except Exception as e:
        client.close()
        return {"success": False, "error": str(e)}
