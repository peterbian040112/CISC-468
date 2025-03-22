# mdns_discovery.py
# This module provides mDNS service registration and peer discovery using zeroconf

from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo, ServiceListener
import socket

SERVICE_TYPE = "_p2pfileshare._tcp.local."
SERVICE_NAME = "PythonPeer._p2pfileshare._tcp.local."
PORT = 9000

class PeerListener(ServiceListener):
    """
    Custom listener for discovered mDNS services.
    Calls the provided callback with formatted peer info.
    """
    def __init__(self, callback):
        self.callback = callback

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port
            self.callback(f"{name} - {ip}:{port}")


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

def start_discovery(callback):
    """
    Starts browsing the local network for other peers using mDNS.
    Calls the callback with each discovered peer.
    """
    zeroconf = Zeroconf()
    listener = PeerListener(callback)
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

def register_service():
    """
    Registers this peer as a discoverable mDNS service.
    Returns the Zeroconf object (to keep it alive).
    """
    zeroconf = Zeroconf()
    local_ip = get_local_ip()
    ip = socket.inet_aton(local_ip)
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[ip],
        port=PORT,
        properties={"version": "1.0"},
        server="python-peer.local."
    )
    zeroconf.register_service(info)
    local_id = f"{SERVICE_NAME} - {local_ip}:{PORT}"
    return zeroconf, local_id


