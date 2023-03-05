import base64
import os
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
def _generate_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return (kdf.derive(passphrase.encode()))


def merged_key(key: bytes, passphrase: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    if not salt:
        salt = os.urandom(16)
    generated_key = _generate_key(passphrase, salt)
    decoded_key = base64.urlsafe_b64decode(key)

    return base64.urlsafe_b64encode(bytes(a ^ b  for a, b in zip(decoded_key, generated_key))), salt


def encrypt(plaintext: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext.encode())


def decrypt(cyphertext: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(cyphertext).decode()
