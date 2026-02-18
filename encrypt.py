import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode

# derive key from password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    cipher = Fernet(key)

    with open(filename, "rb") as f:
        data = f.read()

    encrypted = cipher.encrypt(data)

    with open(filename + ".enc", "wb") as f:
        f.write(salt + encrypted)

    print("File encrypted.")

def decrypt_file(filename, password):
    with open(filename, "rb") as f:
        data = f.read()

    salt = data[:16]
    encrypted_data = data[16:]

    key = generate_key(password, salt)
    cipher = Fernet(key)

    decrypted = cipher.decrypt(encrypted_data)

    output_file = filename.replace(".enc", "")

    with open(output_file, "wb") as f:
        f.write(decrypted)

    print("File decrypted.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print(" encrypt <file>")
        print(" decrypt <file.enc>")
        sys.exit()

    mode = sys.argv[1]
    file = sys.argv[2]
    password = input("Password: ")

    if mode == "encrypt":
        encrypt_file(file, password)
    elif mode == "decrypt":
        decrypt_file(file, password)
