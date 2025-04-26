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
import hashlib
import getpass
from datetime import datetime
from utils.aes_encryption import AESEncryption
from utils.rsa_encryption import RSAEncryption
from utils.file_operations import compress_folder, git_commit, decompress_folder
from logging_config import setup_logging
import pyzipper
import sys

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


class DataFolderManager:
    """Handles operations related to finding and cleaning data folders."""

    @staticmethod
    def find_latest_data_folder():
        """Find the latest data folder based on naming patterns."""
        pattern1 = re.compile(r'data_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}')
        pattern2 = re.compile(r'data')
        folders = [f for f in os.listdir() if os.path.isdir(f) and (pattern1.match(f) or pattern2.match(f))]
        if not folders:
            logger.error("No folder matching the patterns 'data' or 'data_dd_mm_yyyy_HH_MM_SS' found.")
            raise FileNotFoundError("No folder matching the patterns 'data' or 'data_dd_mm_yyyy_HH_MM_SS' found.")
        latest_folder = max(folders, key=os.path.getmtime)
        logger.info(f"Latest data folder found: {latest_folder}")
        return latest_folder

    @staticmethod
    def _clean_old_files(pattern, exclude_file, description):
        """Helper method to clean up old files matching a pattern."""
        for file in os.listdir():
            if re.match(pattern, file) and file != exclude_file:
                os.remove(file)
                logger.info(f"Old {description} deleted: {file}")

    @staticmethod
    def _clean_old_folders(pattern):
        """Helper method to clean up old folders matching a pattern."""
        for folder in os.listdir():
            if os.path.isdir(folder) and re.match(pattern, folder):
                try:
                    os.rmdir(folder)
                    logger.info(f"Data folder deleted: {folder}")
                except OSError:
                    logger.warning(f"Failed to delete folder: {folder}")


class FileChecksum:
    """Handles checksum generation for files."""

    @staticmethod
    def generate_checksum(file_path):
        """Generate a SHA-256 checksum for a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        logger.info(f"Checksum generated for file: {file_path}")
        return sha256_hash.hexdigest()


def extract_pem_files(zip_path, extract_to="vault", password=None):
    """Extract .pem files from an encrypted .zip file."""
    os.makedirs(extract_to, exist_ok=True)
    try:
        if not password:
            logger.error("Password cannot be empty.")
            print("Password cannot be empty. Please try again.")
            return False
        logger.info(f"Attempting to extract .pem files from '{zip_path}'...")
        with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
            zip_ref.pwd = password.encode()
            zip_ref.extractall(extract_to)
        logger.info(f".pem files successfully extracted to '{extract_to}'.")
        return True
    except (RuntimeError, pyzipper.BadZipFile) as e:
        logger.error(f"Failed to extract .pem files: {e}")
        print("Incorrect password or extraction error. Please try again.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        print("An unexpected error occurred. Please try again.")
        return False


def cleanup_pem_files(extract_to="vault"):
    """Remove only extracted .pem files, leaving the directory intact."""
    logger.info(f"Cleaning up extracted .pem files in '{extract_to}'...")
    for file in os.listdir(extract_to):
        file_path = os.path.join(extract_to, file)
        if os.path.isfile(file_path) and file.endswith(".pem"):
            os.remove(file_path)
            logger.debug(f"Deleted file: {file_path}")
    logger.info("Cleanup of .pem files completed.")


def find_latest_zip_file(directory="vault", pattern=r'\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}_[a-zA-Z0-9]+_keys\.zip'):
    """Find the latest .zip file in the specified directory based on the timestamp in the filename."""
    zip_files = [f for f in os.listdir(directory) if re.match(pattern, f)]
    if not zip_files:
        logger.error("No .zip files matching the pattern found in the directory.")
        raise FileNotFoundError("No .zip files matching the pattern found in the directory.")
    latest_zip = max(zip_files, key=lambda f: os.path.getmtime(os.path.join(directory, f)))
    logger.info(f"Latest .zip file found: {latest_zip}")
    return os.path.join(directory, latest_zip)


def find_latest_pem_date_str(directory="vault", pattern=r'(private_key|public_key)_(\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})\.pem'):
    """Find the latest date_str from .pem files in the specified directory."""
    pem_files = [f for f in os.listdir(directory) if re.match(pattern, f)]
    if not pem_files:
        logger.error("No .pem files matching the pattern found in the directory.")
        raise FileNotFoundError("No .pem files matching the pattern found in the directory.")
    latest_pem = max(pem_files, key=lambda f: os.path.getmtime(os.path.join(directory, f)))
    date_str = re.search(pattern, latest_pem).group(2)
    logger.info(f"Latest .pem file date_str found: {date_str}")
    return date_str

class FolderChecksum:
    """Handles checksum generation and validation for folders."""

    @staticmethod
    def generate_folder_checksum(folder_path):
        """Generate an MD5 checksum for the contents of a folder."""
        md5_hash = hashlib.md5()
        for root, dirs, files in os.walk(folder_path):
            for file in sorted(files):  # Sort files to ensure consistent hash
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        md5_hash.update(byte_block)
        logger.info(f"Checksum generated for folder: {folder_path}")
        return md5_hash.hexdigest()

    @staticmethod
    def validate_folder_checksum(folder_path, checksum_file):
        """Validate the folder checksum against the checksum stored in a file."""
        with open(checksum_file, "r") as f:
            stored_checksum = f.read().strip()
        current_checksum = FolderChecksum.generate_folder_checksum(folder_path)
        return stored_checksum == current_checksum

def find_latest_hash_file(directory="vault", pattern=r'\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}_data_hash\.md5'):
    """Find the latest hash file in the specified directory based on the timestamp in the filename."""
    hash_files = [f for f in os.listdir(directory) if re.match(pattern, f)]
    if not hash_files:
        logger.info("No hash files found in the directory.")
        return None
    latest_hash_file = max(hash_files, key=lambda f: os.path.getmtime(os.path.join(directory, f)))
    logger.info(f"Latest hash file found: {latest_hash_file}")
    return os.path.join(directory, latest_hash_file)

def main():
    try:
        # Find the latest data folder
        folder_path = DataFolderManager.find_latest_data_folder()

        # Create the 'vault' directory if it doesn't exist
        vault_dir = "vault"
        os.makedirs(vault_dir, exist_ok=True)

        # Find the latest hash file for validation
        latest_hash_file = find_latest_hash_file(vault_dir)

        if latest_hash_file:
            logger.info(f"Validating folder checksum against the latest hash file: {latest_hash_file}")
            if FolderChecksum.validate_folder_checksum(folder_path, latest_hash_file):
                logger.info("Folder checksum matches the stored hash. No changes detected. Exiting script.")
                print("No changes detected in the folder. Exiting script.")
                sys.exit(1)  # Exit the script no changes detected
            else:
                logger.info("Folder checksum mismatch. Proceeding with encryption...")
        else:
            logger.info("No existing hash file found. Proceeding with encryption...")

        # Generate a new timestamp for encryption and reuse it for all related files
        encrypt_date_str = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")

        # Generate a new hash file and store it in the vault
        folder_hash_file = os.path.join(vault_dir, f"{encrypt_date_str}_{folder_path}_hash.md5")
        folder_checksum = FolderChecksum.generate_folder_checksum(folder_path)
        with open(folder_hash_file, "w") as f:
            f.write(folder_checksum)
        logger.info(f"New hash file generated and stored: {folder_hash_file}")

        # Prompt for the password once
        password = getpass.getpass("Enter the password for the .zip file and private key: ")

        # Find the latest .zip file generated by generate.py
        zip_path = find_latest_zip_file()
        extract_to = vault_dir

        # Keep asking for the password until extraction succeeds
        while True:
            password = getpass.getpass("Enter the password for the .zip file and private key: ")
            if extract_pem_files(zip_path, extract_to, password):
                break

        # Find the latest date_str from the extracted .pem files
        pem_date_str = find_latest_pem_date_str(extract_to)

        # Initialize RSA encryption with the extracted .pem files
        rsa_encryption = RSAEncryption(
            private_key_path=f"{extract_to}/private_key_{pem_date_str}.pem",
            public_key_path=f"{extract_to}/public_key_{pem_date_str}.pem",
            private_key_password=password
        )

        # Generate a compressed file name based on the encryption timestamp
        compressed_file = os.path.join(vault_dir, f'{encrypt_date_str}_data.zip')

        # Generate AES key and IV
        aes_key = AESEncryption.generate_key()
        iv = AESEncryption.generate_iv()

        # Compress the folder
        logger.info(f"Compressing folder: {folder_path}")
        compress_folder(folder_path, compressed_file[:-4], compression='store')
        logger.info(f"Folder compressed into: {compressed_file}")

        # Generate checksum for the compressed file
        checksum = FileChecksum.generate_checksum(compressed_file)
        checksum_file = os.path.join(vault_dir, f'{encrypt_date_str}_checksum.sha256')
        with open(checksum_file, 'w') as f:
            f.write(checksum)
        logger.info(f"Checksum stored in: {checksum_file}")

        # Encrypt the AES key using RSA
        encrypted_aes_key = rsa_encryption.encrypt_key(aes_key)
        encrypted_key_file = os.path.join(vault_dir, f'{encrypt_date_str}_encrypted_aes_key.bin')
        with open(encrypted_key_file, 'wb') as f:
            f.write(encrypted_aes_key)
        logger.info(f"Encrypted AES key stored in: {encrypted_key_file}")

        # Encrypt the compressed file using AES
        encrypted_file = os.path.join(vault_dir, f'{encrypt_date_str}_data.zip.enc')
        AESEncryption.encrypt_file(compressed_file, aes_key, iv)
        logger.info(f"Compressed file encrypted into: {encrypted_file}")

        # Delete the original compressed file
        os.remove(compressed_file)
        logger.info(f"Original compressed file deleted: {compressed_file}")

    except Exception as e:
        logger.exception("An error occurred during the encryption process.")
        print(f"An error occurred: {e}")

    finally:
        # Cleanup extracted .pem files
        cleanup_pem_files()


if __name__ == "__main__":
    main()
