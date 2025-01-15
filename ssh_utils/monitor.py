from ssh_utils.ssh_client import SSHClient

def monitor_container(host, username, password, container_id):
    client = SSHClient(host, username, password)
    if not client.connect():
        return {"success": False, "error": "Failed to connect to server."}

    command = f"docker stats {container_id} --no-stream --format '{{{{json .}}}}'"
    try:
        output, error = client.execute(command)
        client.close()
        if error:
            return {"success": False, "error": error}
        return {"success": True, "stats": output}
    except Exception as e:
        client.close()
        return {"success": False, "error": str(e)}

