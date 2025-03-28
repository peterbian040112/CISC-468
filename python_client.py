# python_client.py
# P2P Secure File Sharing UI with real mDNS discovery (Zeroconf)

import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import threading
import os

import hashlib

import mdns_discovery  # Custom module for mDNS discovery

import socket, json
from rsa_utils import load_keys, serialize_public_key

from trust_store import verify_peer_identity

import base64




class P2PGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Secure File Sharing")

        self.private_key, self.public_key = load_keys()

        self.connected_peer = None
        
        # Peer list UI
        peer_frame = tk.LabelFrame(root, text="Peers", padx=10, pady=5)
        peer_frame.grid(row=0, column=0, padx=10, pady=10)
        self.peer_listbox = tk.Listbox(peer_frame, width=50, height=8, selectmode=tk.SINGLE)
        self.peer_listbox.pack()
        tk.Button(peer_frame, text="Refresh Peers", command=self.refresh_peers).pack(pady=5)
        tk.Button(peer_frame, text="Connect to Selected Peer", command=self.connect_to_peer).pack(pady=5)

        # File list UI
        file_frame = tk.LabelFrame(root, text="Shared Files", padx=10, pady=5)
        file_frame.grid(row=0, column=1, padx=10, pady=10)
        self.file_listbox = tk.Listbox(file_frame, width=50, height=8, selectmode=tk.MULTIPLE)
        self.file_listbox.pack()
        tk.Button(file_frame, text="Request Selected Files", command=self.request_files).pack(pady=5)
        tk.Button(peer_frame, text="Send File to Selected Peer", command=self.send_file_to_peer).pack(pady=5)


        # Log display
        log_frame = tk.LabelFrame(root, text="Log", padx=10, pady=5)
        log_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10)
        self.log_text = tk.Text(log_frame, height=10, width=100, state="disabled")
        self.log_text.pack()

        # Start mDNS service registration
        self.zeroconf, self.local_peer_id = mdns_discovery.register_service()

        # Start background peer discovery (initial)
        threading.Thread(target=self.start_discovery, daemon=True).start()

    def connect_to_peer(self):
        selected = self.peer_listbox.curselection()
        if not selected:
            messagebox.showwarning("No peer selected", "Please select a peer to connect.")
            return

        peer_str = self.peer_listbox.get(selected[0])
        try:
            addr_part = peer_str.split(" - ")[-1]
            ip, port = addr_part.split(":")
            port = int(port)
        except Exception:
            self.log("Failed to parse peer address.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                self.log(f"Connected to {ip}:{port}")

                # Send public key
                msg = {
                    "type": "key_exchange",
                    "public_key": serialize_public_key(self.public_key)
                }
                s.sendall(json.dumps(msg).encode())

                # Receive peer's public key
                data = s.recv(4096).decode()
                response = json.loads(data)
                peer_pub_key = response.get("public_key")
                peer_id = peer_str.split(" - ")[0].strip()

                def prompt_trust(peer_id, fingerprint):
                    return messagebox.askyesno("Untrusted Peer", f"New peer '{peer_id}'\nFingerprint:\n{fingerprint[:32]}...\nTrust this peer?")

                if not verify_peer_identity(peer_id, peer_pub_key, gui_prompt_fn=prompt_trust):
                    self.log(f"[!] Peer '{peer_id}' fingerprint mismatch or untrusted.")
                    messagebox.showerror("Security Alert", f"Could not verify peer identity:\n{peer_id}")
                    return

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                s2.connect((ip, port))
                request = {"type": "get_file_list"}
                s2.sendall(json.dumps(request).encode())

                response = json.loads(s2.recv(4096).decode())
                if response["type"] == "file_list":
                    self.file_listbox.delete(0, tk.END)
                    for file in response["files"]:
                        display = f"{file['name']} ({file['size']}B)"
                        self.file_listbox.insert(tk.END, display)
                    self.log(f"Connected to {ip}:{port} to request file list.")
                else:
                    self.log("Failed to receive file list.")
            self.connected_peer = (ip, port)

        except Exception as e:
            self.log(f"Connection failed: {e}")


    def refresh_peers(self):
        """
        Called when user clicks 'Refresh Peers'.
        Clears the peer list and restarts discovery.
        """
        self.peer_listbox.delete(0, tk.END)
        self.log("Refreshing peer list...")
        threading.Thread(target=self.start_discovery, daemon=True).start()

    def start_discovery(self):
        """
        Starts peer discovery via mDNS, using callback to update UI.
        """
        mdns_discovery.start_discovery(self.add_peer_to_list)

    def add_peer_to_list(self, peer_str):
        """
        Adds a discovered peer to the listbox in the GUI.
        Marks self as [local] if matched.
        """
        display_str = peer_str
        if peer_str == self.local_peer_id:
            display_str = "[local] " + peer_str

        # Prevent duplicate entries
        if display_str not in self.peer_listbox.get(0, tk.END):
            self.peer_listbox.insert(tk.END, display_str)
            self.log(f"Discovered peer: {display_str}")

    def request_files(self):
        """
        Send file request to selected peer, receive file(s), and save to downloads/.
        """
        if not self.connected_peer:
            messagebox.showwarning("No peer connected", "Please connect to a peer first.")
            return

        ip, port = self.connected_peer

        selected_files = [self.file_listbox.get(i).split(" (")[0] for i in self.file_listbox.curselection()]
        if not selected_files:
            messagebox.showwarning("No file selected", "Please select files to request.")
            return

        os.makedirs("downloads", exist_ok=True)

        for fname in selected_files:
            try:
                self.log(f"Requesting file: {fname}")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((ip, port))
                    request = {
                        "type": "file_request",
                        "filename": fname
                    }
                    s.sendall(json.dumps(request).encode())

                    chunks = []
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)

                    data = b"".join(chunks).decode()
                    response = json.loads(data)

                    if response["type"] == "file_transfer":
                        file_data = base64.b64decode(response["content"])
                        with open(os.path.join("downloads", fname), "wb") as f:
                            f.write(file_data)
                        self.log(f"Downloaded: {fname} ({len(file_data)} bytes)")
                    elif response["type"] == "refused":
                        self.log(f"Refused by peer: {fname}")
                    else:
                        self.log(f"Unexpected response for {fname}")
            except Exception as e:
                self.log(f"[!] Error requesting {fname}: {e}")

    def send_file_to_peer(self):
        if not self.connected_peer:
            messagebox.showwarning("Not Connected", "Please connect to a peer first.")
            return

        filepath = filedialog.askopenfilename(title="Select file to send")
        if not filepath:
            return  # User cancelled

        filename = os.path.basename(filepath)
        try:
            with open(filepath, "rb") as f:
                data = f.read()
                b64_data = base64.b64encode(data).decode()
                sha256 = hashlib.sha256(data).hexdigest()

            ip, port = self.connected_peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                request = {
                    "type": "send_file_request",
                    "filename": filename,
                    "content": b64_data,
                    "hash": sha256
                }
                s.sendall(json.dumps(request).encode())

                response = json.loads(s.recv(2048).decode())
                if response["type"] == "accept":
                    self.log(f"[✓] Peer accepted file: {filename}")
                else:
                    self.log(f"[!] Peer refused file: {filename}")

        except Exception as e:
            self.log(f"[!] Failed to send file: {e}")


    def log(self, msg):
        """
        Writes a message to the log window.
        """
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"> {msg}\n")
        self.log_text.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PGUI(root)
    root.mainloop()
    app.zeroconf.close()

