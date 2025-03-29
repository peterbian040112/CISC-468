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

from aes_utils import aes_decrypt
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

from sts_utils import generate_ecdh_keypair, derive_shared_key, sign_data, verify_signature
from aes_utils import aes_decrypt


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
                chunks = []
                while True:
                    try:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        try:
                            data = b"".join(chunks).decode()
                            request = json.loads(data)
                            break
                        except json.JSONDecodeError:
                            continue
                    except Exception as e:
                        print(f"[!] Error receiving data: {e}")
                        return

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
                    print(f"[✓] {len(files)} file(s) found.")

                elif request["type"] == "file_request":
                    fname = request.get("filename")
                    print(f"[*] File requested: {fname}")

                    user_input = input(f"[?] Allow peer to download file '{fname}'? (y/n): ").strip().lower()
                    allow = (user_input == "y")

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
                    peer_ecdh_pub_b64 = request.get("ecdh_pub")
                    peer_signature_b64 = request.get("signature")

                    peer_ecdh_pub = base64.b64decode(peer_ecdh_pub_b64)
                    peer_signature = base64.b64decode(peer_signature_b64)

                    # Verify peer's RSA signature
                    if not verify_signature(public_key, peer_ecdh_pub, peer_signature):
                        print("[!] Invalid RSA signature from sender.")
                        conn.sendall(json.dumps({"type": "refused", "reason": "bad_signature"}).encode())
                        return

                    # Generates local ECDH public and private key pair
                    local_ecdh_priv, local_ecdh_pub = generate_ecdh_keypair()

                    # Sign local ECDH public key
                    local_signature = sign_data(private_key, local_ecdh_pub)

                    response = {
                        "type": "sts_response",
                        "ecdh_pub": base64.b64encode(local_ecdh_pub).decode(),
                        "signature": base64.b64encode(local_signature).decode()
                    }
                    conn.sendall(json.dumps(response).encode())

                    chunks = []
                    while True:
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        try:
                            data2 = b''.join(chunks).decode()
                            file_payload = json.loads(data2)
                            break
                        except json.JSONDecodeError:
                            continue

                    if file_payload["type"] != "file_transfer":
                        print("[!] Expected file_transfer but got:", file_payload.get("type"))
                        return

                    ciphertext_b64 = file_payload["content"]
                    hash_val = file_payload["hash"]

                    # Derive AES key from STS
                    aes_key = derive_shared_key(local_ecdh_priv, peer_ecdh_pub)

                    try:
                        plaintext = aes_decrypt(aes_key, ciphertext_b64)
                        computed_hash = hashlib.sha256(plaintext).hexdigest()

                        if computed_hash != hash_val:
                            print(f"[!] Hash mismatch! Expected {hash_val[:8]}..., got {computed_hash[:8]}...")
                            conn.sendall(json.dumps({"type": "refused", "reason": "hash_mismatch"}).encode())
                            return

                        user_input = input(f"[?] Accept file '{fname}' from peer? (y/n): ").strip().lower()
                        
                        from secure_storage import encrypt_and_store_file, derive_key_from_password

                        if user_input == "y":
                            os.makedirs("downloads_encrypted", exist_ok=True)

                            # Ask for password (or reuse one you stored earlier)
                            password = input("Enter your storage password to decrypt: ")
                            salt = b"p2p-storage-salt"
                            storage_key = derive_key_from_password(password, salt)

                            encrypt_and_store_file(plaintext, fname, storage_key)

                            print(f"[✓] File securely saved to downloads_encrypted/{fname}")
                            conn.sendall(json.dumps({"type": "accept"}).encode())

                        else:
                            conn.sendall(json.dumps({"type": "refused"}).encode())

                    except Exception as e:
                        print(f"[!] Decryption failed: {e}")
                        conn.sendall(json.dumps({"type": "refused", "reason": "decryption_error"}).encode())

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
