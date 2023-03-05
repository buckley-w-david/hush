import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
def generate_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_passphrase(plaintext: str, passphrase: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    key = generate_key(passphrase, salt)
    f = Fernet(key)

    return f.encrypt(plaintext.encode()), base64.urlsafe_b64encode(salt)


def decrypt_passphrase(cyphertext: bytes, salt: bytes, passphrase: str) -> str:
    key = generate_key(passphrase, base64.urlsafe_b64decode(salt))
    f = Fernet(key)
    return f.decrypt(cyphertext).decode()


def encrypt(plaintext: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext.encode())


def decrypt(cyphertext: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(cyphertext).decode()
