import os
import base64
import hashlib
from aes_utils import aes_encrypt, aes_decrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key_from_password(password: str, salt: bytes, iterations=100_000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_and_store_file(data: bytes, filename: str, key: bytes):
    encrypted = aes_encrypt(key, data)
    with open(os.path.join("downloads_encrypted", filename), "w") as f:
        f.write(encrypted)

def decrypt_file_from_storage(filepath: str, key: bytes) -> bytes:
    with open(filepath, "r") as f:
        ciphertext_b64 = f.read()
    return aes_decrypt(key, ciphertext_b64)
