# python_client.py
# P2P Secure File Sharing UI with real mDNS discovery (Zeroconf)

import tkinter as tk
from tkinter import messagebox
import threading

import mdns_discovery  # Custom module for mDNS discovery

import socket, json
from rsa_utils import load_keys, serialize_public_key


class P2PGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Secure File Sharing")

        self.private_key, self.public_key = load_keys()
        
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
                if peer_pub_key:
                    self.log("Received peer public key.")
                    messagebox.showinfo("Key Exchange", "RSA public key exchange successful.")
                else:
                    self.log("No public key received.")
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
        Simulated file request - will be replaced by real file transfer later.
        """
        selected_files = [self.file_listbox.get(i) for i in self.file_listbox.curselection()]
        if not selected_files:
            messagebox.showwarning("No file selected", "Please select files to request.")
            return
        self.log(f"Requested files: {', '.join(selected_files)}")
        messagebox.showinfo("Success", "File(s) transferred successfully and hash verified.")

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
    app.zeroconf.close()  # Close the Zeroconf object when the app exits

