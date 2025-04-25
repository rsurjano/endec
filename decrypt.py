"""
This file is part of the Endec project developed by Arnat Technologies.

Endec is a developer-friendly encryption toolkit combining AES-256 and RSA-4096
to securely compress, encrypt, and decrypt sensitive data. It includes RSA key
generation, checksum verification, and encrypted backups with a unified CLI for
seamless integration into workflows.

Endec is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Endec is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Endec.
If not, see <https://www.gnu.org/licenses/>.

Copyright (C) 2025 Arnat Technologies
"""
import os
import re
import logging
from utils.aes_encryption import AESEncryption
from utils.rsa_encryption import RSAEncryption
from utils.file_operations import decompress_folder
from logging_config import setup_logging
import hashlib
from datetime import datetime
from encrypt import cleanup_pem_files, extract_pem_files  # Importar funciones necesarias de encrypt.py

# Configuración de logging
setup_logging()
logger = logging.getLogger(__name__)


class FileChecksum:
    """Maneja la generación de checksums para archivos."""

    @staticmethod
    def generate_checksum(file_path):
        """Genera un checksum SHA-256 para un archivo."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        logger.info(f"Checksum generado para el archivo: {file_path}")
        return sha256_hash.hexdigest()


def find_latest_file(directory, pattern):
    """Encuentra el archivo más reciente que coincida con un patrón."""
    matching_files = [
        f for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f)) and re.match(pattern, f)
    ]
    if not matching_files:
        logger.error(f"No se encontró ningún archivo que coincida con el patrón '{pattern}' en el directorio '{directory}'.")
        raise FileNotFoundError(f"No se encontró ningún archivo que coincida con el patrón '{pattern}' en el directorio '{directory}'.")
    latest_file = max(matching_files, key=lambda f: os.path.getmtime(os.path.join(directory, f)))
    logger.info(f"Archivo más reciente encontrado: {latest_file}")
    return os.path.join(directory, latest_file)


def decrypt():
    try:
        # Generate a timestamp for file naming
        decrypt_date_str = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")

        # Find the latest encrypted data file
        data_pattern = r'data_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip\.enc'
        encrypted_file = find_latest_file("vault", data_pattern)
        logger.info(f"Latest encrypted data file identified: {encrypted_file}")

        # Extract the date string from the data file name
        data_date_str = re.search(r'data_(\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})', encrypted_file).group(1)

        # Find the latest keys file
        keys_pattern = r'.*_keys_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip'
        keys_zip_file = find_latest_file("vault", keys_pattern)
        logger.info(f"Latest keys file identified: {keys_zip_file}")

        # Extract the date string from the keys file name
        keys_date_str = re.search(r'keys_(\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})', keys_zip_file).group(1)

        # Define related paths
        encrypted_key_file = os.path.join("vault", f'{decrypt_date_str}_encrypted_aes_key_{data_date_str}.bin')
        checksum_file = os.path.join("vault", f'{decrypt_date_str}_checksum_{data_date_str}.sha256')

        # Prompt for the password to decrypt the private key
        password = input("Enter the password for the private key: ").strip()

        # Validate and extract keys from the zip file
        if not extract_pem_files(keys_zip_file, "vault", password):
            logger.error("Failed to extract keys from the zip file. Exiting.")
            return
        logger.info("Keys successfully extracted to the 'vault' directory.")

        # Define private and public key paths
        private_key_path = os.path.join("vault", f"private_key_{keys_date_str}.pem")
        public_key_path = os.path.join("vault", f"public_key_{keys_date_str}.pem")

        # Load the encrypted AES key
        with open(encrypted_key_file, 'rb') as f:
            encrypted_aes_key = f.read()
        logger.info(f"Encrypted AES key loaded from: {encrypted_key_file}")

        # Load the checksum
        with open(checksum_file, 'r') as f:
            original_checksum = f.read().strip()
        logger.info(f"Checksum loaded from: {checksum_file}")

        # Initialize RSA decryption
        rsa_encryption = RSAEncryption(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            private_key_password=password
        )

        # Decrypt the AES key
        aes_key = rsa_encryption.decrypt_key(encrypted_aes_key)
        logger.info("AES key successfully decrypted.")

        # Decrypt the encrypted file
        AESEncryption.decrypt_file(encrypted_file, aes_key)
        logger.info(f"Encrypted file decrypted: {encrypted_file}")

        # Remove the '.enc' extension to get the decrypted ZIP file
        decrypted_file = encrypted_file[:-4]

        # Verify the checksum of the decrypted file
        decrypted_checksum = FileChecksum.generate_checksum(decrypted_file)
        if decrypted_checksum == original_checksum:
            logger.info("Checksum verification passed.")
        else:
            logger.error("Checksum verification failed.")
            return

        # Decompress the decrypted ZIP file into a folder
        output_folder = f"{decrypt_date_str}_data_{data_date_str}"
        decompress_folder(decrypted_file, output_folder)
        logger.info(f"Decrypted file decompressed into folder: {output_folder}")

        # Remove the intermediate decrypted ZIP file
        os.remove(decrypted_file)
        logger.info(f"Intermediate decrypted ZIP file removed: {decrypted_file}")

        # Clean up extracted .pem files
        cleanup_pem_files("vault")
        logger.info("Extracted .pem files cleaned up.")

    except Exception as e:
        logger.exception("An error occurred during the decryption process.")
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    decrypt()
