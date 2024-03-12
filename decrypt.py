from cryptography.fernet import Fernet
import getpass
import base64

# Generate a key based on the password
def generate_key(password: str) -> bytes:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import os

    salt = b'\x00'*16  # A fixed salt is not recommended for real applications
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

# Decrypt the file
def decrypt_file(file_path: str, key: bytes):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted = file.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        with open(file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        print("File decrypted successfully.")
    except Exception as e:
        print("Decryption failed:", e)

if __name__ == "__main__":
    password = getpass.getpass("Enter decryption password: ")
    key = generate_key(password)
    decrypt_file('client_secret.json', key)