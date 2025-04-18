# Encryption and Decryption Script

This project provides a robust solution for securely storing and managing critical data using state-of-the-art encryption mechanisms. It is designed to protect highly sensitive information by combining AES-256 encryption for data and RSA-4096 encryption for key management. The project also includes features for verifying data integrity, securely storing RSA keys, and managing encrypted backups. A unified CLI interface (`__main__.py`) simplifies the execution of encryption, decryption, and key generation tasks.

---

## Objective

The primary goal of this project is to provide a **secure and reliable mechanism** for storing critical data using the **strongest encryption standards available**. This ensures that sensitive information remains protected from unauthorized access, even in high-risk environments.

---

## Features

- **Unified CLI**: Run encryption, decryption, and key generation tasks using a single entry point (`__main__.py`).
- **AES Encryption**: Encrypts data using AES-256 with a randomly generated key and IV.
- **RSA Encryption**: Encrypts the AES key using RSA-4096 for secure key sharing.
- **Checksum Verification**: Ensures data integrity by generating and verifying SHA-256 checksums.
- **Data Compression**: Compresses data folders into ZIP archives before encryption.
- **Key Management**: Generates and securely stores RSA public/private key pairs in encrypted archives.
- **Decryption**: Decrypts and decompresses encrypted files back into their original form.
- **Hook Integration**: Automatically runs `hook.py` after encryption to perform additional tasks like copying files.
- **Logging**: Detailed logs for all operations are stored in `project.log`.

---

## Prerequisites

1. **Python**: Ensure Python 3.11+ is installed.
2. **Dependencies**: Install the required Python libraries using `pip`:

   ```sh
   pip install -r requirements.txt
   ```

---

## Usage

### 1. Unified CLI Interface

The `__main__.py` script provides a unified CLI to run encryption, decryption, and key generation tasks.

#### Steps

1. Run the script without arguments to see the options:

   ```sh
   python .
   ```

2. Select an option:
   - `1` or `encrypt`: Run the encryption script.
   - `2` or `decrypt`: Run the decryption script.
   - `3` or `generate`: Run the RSA key generation script.

#### Example

To encrypt data:

```sh
python . encrypt
```

To decrypt data:

```sh
python . decrypt
```

To generate RSA keys:

```sh
python . generate
```

Alternatively, you can use numeric commands:

```sh
python . 1  # Encrypt
python . 2  # Decrypt
python . 3  # Generate RSA keys
```

---

### 2. Hook Integration

The `hook.py` script is automatically executed after the encryption process (`encrypt.py`) if it exists. It performs additional tasks, such as copying encrypted files to a destination folder specified in the `.env` file.

#### Steps

1. Ensure the `.env` file exists in the project directory with the following content:

   ```plaintext
   DESTINATION_FOLDER=~/path/to/destination
   ```

2. After running the encryption process, `hook.py` will:
   - Copy files from the `vault/` directory to the destination folder.
   - Skip files that already exist in the destination.

---

### 3. Encrypt Data

The `encrypt.py` script compresses, encrypts, and generates necessary files for secure storage.

#### Steps

1. Place the data folder(s) you want to encrypt in the `data/` directory.

2. Run the encryption script via the CLI:

   ```sh
   python . encrypt
   ```

3. The script will:
   - Compress the latest `data` folder into a ZIP file.
   - Encrypt the ZIP file using AES-256.
   - Encrypt the AES key using RSA-4096.
   - Generate a SHA-256 checksum for the ZIP file.
   - Move the encrypted files to the `vault/` directory.
   - Automatically execute `hook.py` to copy files to the destination folder.

#### Output Files

- `vault/data_<timestamp>.zip.enc`: Encrypted ZIP file.
- `vault/encrypted_aes_key_<timestamp>.bin`: Encrypted AES key.
- `vault/checksum_<timestamp>.sha256`: SHA-256 checksum.

---

### 4. Decrypt Data

The `decrypt.py` script decrypts and decompresses the encrypted files.

#### Steps

1. Ensure the following files are present in the `vault/` directory:
   - `data_<timestamp>.zip.enc`
   - `encrypted_aes_key_<timestamp>.bin`
   - `checksum_<timestamp>.sha256`
   - The latest RSA key archive (e.g., `<hint>_keys_<timestamp>.zip`).

2. Run the decryption script via the CLI:

   ```sh
   python . decrypt
   ```

3. The script will:
   - Decrypt the AES key using the RSA private key.
   - Decrypt the ZIP file using the AES key.
   - Verify the checksum of the decrypted ZIP file.
   - Decompress the ZIP file into the `data/` directory.

#### Output

- Decrypted data will be extracted into a folder named `data_<timestamp>`.

---

### 5. Generate RSA Keys

The `generate.py` script generates a pair of RSA keys (private and public) and securely stores them in an encrypted archive.

#### Steps

1. Run the script via the CLI:

   ```sh
   python . generate
   ```

2. The script will:
   - Generate a new RSA private/public key pair.
   - Prompt for a password to encrypt the private key and archive.
   - Save the keys in an encrypted ZIP file in the `vault/` directory.

#### Output Files

- `<hint>_keys_<timestamp>.zip`: Encrypted archive containing the RSA keys.

---

## Real Use Cases

### 1. **Secure Backup of Sensitive Data**
   - Use this project to encrypt and securely store backups of sensitive files, such as financial records, legal documents, or intellectual property.

### 2. **Data Sharing in High-Security Environments**
   - Share encrypted data with collaborators by providing them with the encrypted AES key and the public RSA key.

### 3. **Long-Term Archival**
   - Protect critical data archives for long-term storage, ensuring they remain secure even if accessed years later.

### 4. **Compliance with Data Protection Regulations**
   - Use strong encryption to comply with regulations like GDPR, HIPAA, or PCI DSS for protecting sensitive data.

---

## File Structure

```markdown
.
├── __main__.py               # Unified CLI for encryption, decryption, and key generation
├── encrypt.py                # Main script for encryption
├── decrypt.py                # Main script for decryption
├── generate.py               # Script to generate RSA keys
├── hook.py                   # Script to copy files after encryption
├── logging_config.py         # Logging configuration
├── requirements.txt          # Python dependencies
├── vault/                    # Directory for encrypted files and keys
│   ├── data_<timestamp>.zip.enc
│   ├── encrypted_aes_key_<timestamp>.bin
│   ├── checksum_<timestamp>.sha256
│   └── <hint>_keys_<timestamp>.zip
├── data/                     # Directory for decrypted data
├── utils/                    # Utility scripts for encryption and file operations
│   ├── aes_encryption.py     # AES encryption/decryption
│   ├── rsa_encryption.py     # RSA encryption/decryption
│   └── file_operations.py    # File compression and Git integration
├── project.log               # Log file for all operations
├── README.md                 # Project documentation
└── .vscode/                  # VS Code configuration
```

---

## Logging

All logs are stored in `project.log`. Logs include detailed information about encryption, decryption, and file operations.

---

## Security Notes

- Keep the RSA private key archive (e.g., `<hint>_keys_<timestamp>.zip`) secure. It is required to decrypt the AES key.
- Do not share the `vault/` directory or the private key with unauthorized users.
- Regularly back up your encrypted files and keys.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
