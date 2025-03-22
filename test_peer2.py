# test_peer2.py
# A headless client that registers itself via mDNS but does NOT discover others

from zeroconf import Zeroconf, ServiceInfo
import socket
import time

SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "PythonPeer2._p2pfileshare._tcp.local."
PORT = 9001

def get_local_ip():
    """
    Returns the local (non-loopback) IP address.
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
    Registers this peer as an mDNS service.
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

if __name__ == "__main__":
    # Register only (no discovery)
    zc = register_service()
    print("[*] Service running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")
        zc.close()

