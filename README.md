# PS-15_Tech-Busters
# Protecting User Password Keys at Rest (on the Disk)

This project implements file encryption and decryption using AES-256, with the file encryption key protected by a user passphrase.

## Features
- Encrypt a file using a randomly generated AES-256 key.
- Protect the AES-256 key using a user-provided passphrase.
- Store the encrypted AES-256 key and salt securely.
- Decrypt the file using the correct passphrase to retrieve the AES-256 key.

## Requirements
- Python 3.x
- `cryptography` library

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/file-encryption-decryption.git
    ```
2. Navigate to the project directory:
    ```bash
    cd file-encryption-decryption
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. To encrypt a file:
    ```python
    from encrypt_decrypt import encrypt_file
    passphrase = "your_secure_password"
    file_path = "example.txt"
    encrypt_file(file_path, passphrase)
    ```

2. To decrypt a file:
    ```python
    from encrypt_decrypt import decrypt_file
    passphrase = "your_secure_password"
    file_path = "example.txt"
    decrypt_file(file_path, passphrase)
    ```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Tests
The `tests/test_cases.txt` file contains various test cases for simple and corner cases.

## Contributing
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.
