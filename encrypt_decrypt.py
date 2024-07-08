import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Function to generate a key from the passphrase using PBKDF2
def generate_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return key

# Function to encrypt the file
def encrypt_file(file_path: str, passphrase: str):
    # Generate a random salt
    salt = os.urandom(16)
    # Generate a random 32-byte file encryption key
    file_encryption_key = os.urandom(32)

    # Derive a key from the passphrase
    derived_key = generate_key_from_passphrase(passphrase, salt)

    # Encrypt the file
    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(file_encryption_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file
    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)

    # Encrypt the file encryption key with the derived key
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_file_encryption_key = encryptor.update(file_encryption_key) + encryptor.finalize()

    # Save the encrypted file encryption key and salt
    with open(file_path + '.key', 'wb') as f:
        f.write(salt + iv + encrypted_file_encryption_key)

# Function to decrypt the file
def decrypt_file(file_path: str, passphrase: str):
    # Read the salt and encrypted file encryption key
    with open(file_path + '.key', 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_file_encryption_key = f.read(32)

    # Derive the key from the passphrase
    derived_key = generate_key_from_passphrase(passphrase, salt)

    # Decrypt the file encryption key
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    file_encryption_key = decryptor.update(encrypted_file_encryption_key) + decryptor.finalize()

    # Read the encrypted file
    with open(file_path + '.enc', 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    # Decrypt the file
    cipher = Cipher(algorithms.AES(file_encryption_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Save the decrypted file
    with open(file_path + '.dec', 'wb') as f:
        f.write(data)

# Example usage:
if __name__ == "__main__":
    passphrase = "securepassword"
    file_path = "example.txt"

    # Encrypt the file
    encrypt_file(file_path, passphrase)
    print(f"{file_path} encrypted successfully.")

    # Decrypt the file
    decrypt_file(file_path, passphrase)
    print(f"{file_path} decrypted successfully.")
