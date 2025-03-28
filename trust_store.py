# trust_store.py
import json
import os
import hashlib

TRUSTED_PEER_FILE = "trusted_peers.json"

def get_fingerprint(pem_str):
    """
    Returns SHA-256 fingerprint of a PEM-formatted RSA public key.
    """
    return hashlib.sha256(pem_str.encode()).hexdigest()

def load_trust_store():
    """
    Loads the trust store from disk, or returns empty if not found.
    """
    if not os.path.exists(TRUSTED_PEER_FILE):
        return {}
    with open(TRUSTED_PEER_FILE, "r") as f:
        return json.load(f)

def save_trust_store(trust_data):
    """
    Saves the trust store to disk.
    """
    with open(TRUSTED_PEER_FILE, "w") as f:
        json.dump(trust_data, f, indent=2)

def verify_peer_identity(peer_id, peer_public_key, gui_prompt_fn=None):
    """
    Verifies the peer's identity using its public key fingerprint.
    If unknown, asks user whether to trust.
    """
    fingerprint = get_fingerprint(peer_public_key)
    trust_store = load_trust_store()

    if peer_id in trust_store:
        if trust_store[peer_id] == fingerprint:
            return True  # Match
        else:
            return False  # Mismatch — possibly an attacker
    else:
        # 🟡 Unknown peer — prompt the user
        if gui_prompt_fn is not None:
            user_accept = gui_prompt_fn(peer_id, fingerprint)
            if user_accept:
                trust_store[peer_id] = fingerprint
                save_trust_store(trust_store)
                return True
        return False

