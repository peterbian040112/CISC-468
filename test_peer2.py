# test_peer2.py
import socket
import threading
import time
import os
import json
import hashlib
from zeroconf import Zeroconf, ServiceInfo
from rsa_utils import load_keys, serialize_public_key

import base64

SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "PythonPeer2._p2pfileshare._tcp.local."
PORT = 9001

def get_local_ip():
    """
    Returns the local (non-loopback) IP address of the host.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def register_service():
    """
    Registers this peer on the local network using mDNS.
    """
    zeroconf = Zeroconf()
    ip = socket.inet_aton(get_local_ip())
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[ip],
        port=PORT,
        properties={"version": "1.0"},
        server="python-peer2.local."
    )
    zeroconf.register_service(info)
    print(f"[✓] Service '{SERVICE_NAME}' registered on {get_local_ip()}:{PORT}")
    return zeroconf

def get_shared_files(folder="shared"):
    """
    Scans the shared directory and returns a list of file info dicts.
    Each dict includes: name, size, and SHA-256 hash of the file.
    """
    files = []
    if not os.path.exists(folder):
        os.makedirs(folder)

    for fname in os.listdir(folder):
        path = os.path.join(folder, fname)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
            files.append({
                "name": fname,
                "size": os.path.getsize(path),
                "hash": sha256
            })
    return files

def start_server(private_key, public_key):
    """
    Starts a TCP socket server to handle incoming requests.
    Supports: RSA key exchange and file list sharing.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    print(f"[*] Server listening on port {PORT}")

    while True:
        conn, addr = server.accept()
        with conn:
            print(f"[+] Connection from {addr}")
            try:
                data = conn.recv(4096).decode()
                request = json.loads(data)

                if request["type"] == "key_exchange":
                    print("[*] Received public key from client.")
                    response = {
                        "type": "key_exchange_response",
                        "public_key": serialize_public_key(public_key)
                    }
                    conn.sendall(json.dumps(response).encode())
                    print("[✓] Sent back our public key.")

                elif request["type"] == "get_file_list":
                    print("[*] Received file list request.")
                    files = get_shared_files()
                    response = {
                        "type": "file_list",
                        "files": files
                    }
                    conn.sendall(json.dumps(response).encode())
                    print(f"[✓] Sent {len(files)} file(s).")
                    
                elif request["type"] == "file_request":
                    fname = request.get("filename")
                    print(f"[*] File requested: {fname}")
                    # Prompt for permission (optional), here we auto-accept:
                    allow = True
                    shared_path = os.path.join("shared", fname)
                    if allow and os.path.exists(shared_path):
                        with open(shared_path, "rb") as f:
                            content = base64.b64encode(f.read()).decode()

                        response = {
                            "type": "file_transfer",
                            "filename": fname,
                            "content": content
                        }
                        conn.sendall(json.dumps(response).encode())
                        print(f"[✓] Sent file: {fname}")
                    else:
                        response = {"type": "refused"}
                        conn.sendall(json.dumps(response).encode())
                        print(f"[!] Refused or not found: {fname}")

                elif request["type"] == "send_file_request":
                    fname = request.get("filename")
                    content = request.get("content")
                    hash_val = request.get("hash")
                    print(f"[*] Incoming file: {fname} (hash: {hash_val[:8]}...)")
                    try:
                        user_input = input(f"[?] Accept file '{fname}' from peer? (y/n): ").strip().lower()
                        if user_input == "y":
                            save_path = os.path.join("downloads", fname)
                            os.makedirs("downloads", exist_ok=True)
                            with open(save_path, "wb") as f:
                                f.write(base64.b64decode(content))
                            print(f"[✓] File saved to downloads/{fname}")
                            conn.sendall(json.dumps({"type": "accept"}).encode())
                        else:
                            print("[!] User refused file.")
                            conn.sendall(json.dumps({"type": "refused"}).encode())
                    except Exception as e:
                        print(f"[!] Error during file receive: {e}")
                        conn.sendall(json.dumps({"type": "refused"}).encode())
                else:
                    print(f"[!] Unknown request type: {request.get('type')}")

            except Exception as e:
                print(f"[!] Error handling request: {e}")

if __name__ == "__main__":
    private_key, public_key = load_keys()
    zc = register_service()
    threading.Thread(target=start_server, args=(private_key, public_key), daemon=True).start()

    print("[*] Peer running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        zc.close()
