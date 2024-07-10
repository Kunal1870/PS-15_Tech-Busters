import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Function to derive a cryptographic key from a passphrase
def derive_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return key

# Function to encrypt a file
def encrypt_file(file_path: str, passphrase: str):
    # Generate a random salt and file encryption key
    salt = os.urandom(16)
    file_key = os.urandom(32)

    # Derive a key from the passphrase
    derived_key = derive_key(passphrase, salt)

    # Read and pad the file contents
    with open(file_path, 'rb') as f:
        data = f.read()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the file data
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(file_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted data to a new file
    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)

    # Encrypt the file encryption key with the derived key
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_file_key = encryptor.update(file_key) + encryptor.finalize()

    # Save the salt, IV, and encrypted file key to a separate file
    with open(file_path + '.key', 'wb') as f:
        f.write(salt + iv + encrypted_file_key)

# Function to decrypt a file
def decrypt_file(file_path: str, passphrase: str):
    # Read the salt, IV, and encrypted file key
    with open(file_path + '.key', 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_file_key = f.read(32)

    # Derive the key from the passphrase
    derived_key = derive_key(passphrase, salt)

    # Decrypt the file encryption key
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    file_key = decryptor.update(encrypted_file_key) + decryptor.finalize()

    # Read the encrypted file data
    with open(file_path + '.enc', 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    # Decrypt the file data
    cipher = Cipher(algorithms.AES(file_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Write the decrypted data to a new file
    with open(file_path + '.dec', 'wb') as f:
        f.write(data)

# Example usage
if __name__ == "__main__":
    passphrase = "securepassword"
    file_path = "example.txt"

    # Encrypt the file
    encrypt_file(file_path, passphrase)
    print(f"{file_path} encrypted successfully.")

    # Decrypt the file
    decrypt_file(file_path, passphrase)
    print(f"{file_path} decrypted successfully.")
