from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_file(file_bytes):
    key = get_random_bytes(32)  # AES-256
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

    return {
        "data": cipher.nonce + tag + ciphertext,
        "key": base64.b64encode(key).decode()
    }

def decrypt_file(encrypted_data, key):
    key = base64.b64decode(key)

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)