import paramiko
import time
import os
import threading
from dotenv import load_dotenv

# Layer 1 — Config
load_dotenv()
SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = int(os.getenv("SSH_PORT", 22))
SSH_USERNAME = os.getenv("SSH_USERNAME")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")

# Layer 2 — SSH Connection
def create_ssh_client():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=SSH_HOST,
        port=SSH_PORT,
        username=SSH_USERNAME,
        password=SSH_PASSWORD
    )
    return client

# Layer 3 — Auto run tail -f and Stream Logs
def stream_logs(log_path="/var/log/auth.log"):
    client = create_ssh_client()
    command = f"tail -n 50 -f {log_path}"
    stdin, stdout, stderr = client.exec_command(command)
    for line in stdout:
        clean_line = line.strip()
        if clean_line:
            yield clean_line





# Layer 4 — Multi-Log Stream Manager (UPDATED)
def start_log_stream(callback=None):
    log_files = [
        "/var/log/auth.log",
        "/var/log/apache2/access.log"
    ]
    for log_path in log_files:
        thread = threading.Thread(
            target=_stream_single_log,
            args=(callback, log_path),
            daemon=True
        )
        thread.start()
        print(f"[*] Streaming {log_path}")

def _stream_single_log(callback, log_path):
    while True:
        try:
            print(f"[*] Connecting to {SSH_HOST} for {log_path}...")
            for line in stream_logs(log_path):
                print(f"[LOG:{log_path}] {line}")
                if callback:
                    callback(line)
        except Exception as e:
            print(f"[!] Connection lost ({log_path}): {e}")
            print("[*] Reconnecting in 5 seconds...")
            time.sleep(5)