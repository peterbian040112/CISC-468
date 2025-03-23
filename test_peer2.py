# test_peer2.py

from zeroconf import Zeroconf, ServiceInfo
import socket
import time
import threading
import json
from rsa_utils import load_keys, serialize_public_key

SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "PythonPeer2._p2pfileshare._tcp.local."
PORT = 9001

def get_local_ip():
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

def start_key_exchange_server(private_key, public_key):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    print(f"[*] RSA Key Exchange Server running on port {PORT}")

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
            except Exception as e:
                print(f"[!] Error: {e}")

if __name__ == "__main__":
    private_key, public_key = load_keys()
    zc = register_service()
    threading.Thread(target=start_key_exchange_server, args=(private_key, public_key), daemon=True).start()

    print("[*] Service running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")
        zc.close()


