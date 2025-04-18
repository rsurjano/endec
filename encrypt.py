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
            logger.error("Password cannot be empty. Exiting.")
            print("Password cannot be empty. Exiting.")
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


def find_latest_zip_file(directory="vault", pattern=r'.*_keys_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip'):
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


def main():
    try:
        # Prompt for the password once
        password = getpass.getpass("Enter the password for the .zip file and private key: ")

        # Find the latest .zip file generated by generate.py
        zip_path = find_latest_zip_file()
        extract_to = "vault"

        # Extract .pem files from the encrypted .zip file
        if not extract_pem_files(zip_path, extract_to, password):
            return

        # Find the latest date_str from the extracted .pem files
        pem_date_str = find_latest_pem_date_str(extract_to)

        # Generate a new timestamp for encryption
        encrypt_date_str = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")

        # Initialize RSA encryption with the extracted .pem files
        rsa_encryption = RSAEncryption(
            private_key_path=f"{extract_to}/private_key_{pem_date_str}.pem",
            public_key_path=f"{extract_to}/public_key_{pem_date_str}.pem",
            private_key_password=password
        )

        # Find the latest data folder
        folder_path = DataFolderManager.find_latest_data_folder()

        # Generate a compressed file name based on the encryption timestamp
        compressed_file = f'data_{encrypt_date_str}.zip'

        # Generate AES key and IV
        aes_key = AESEncryption.generate_key()
        iv = AESEncryption.generate_iv()

        # Compress the folder
        logger.info(f"Compressing folder: {folder_path}")
        compress_folder(folder_path, compressed_file[:-4], compression='store')
        logger.info(f"Folder compressed into: {compressed_file}")

        # Generate checksum for the compressed file
        checksum = FileChecksum.generate_checksum(compressed_file)
        checksum_file = f'checksum_{encrypt_date_str}.sha256'
        with open(checksum_file, 'w') as f:
            f.write(checksum)
        logger.info(f"Checksum stored in: {checksum_file}")

        # Encrypt the AES key using RSA
        encrypted_aes_key = rsa_encryption.encrypt_key(aes_key)
        encrypted_key_file = f'encrypted_aes_key_{encrypt_date_str}.bin'
        with open(encrypted_key_file, 'wb') as f:
            f.write(encrypted_aes_key)
        logger.info(f"Encrypted AES key stored in: {encrypted_key_file}")

        # Encrypt the compressed file using AES
        AESEncryption.encrypt_file(compressed_file, aes_key, iv)
        encrypted_file = f'{compressed_file}.enc'
        logger.info(f"Compressed file encrypted into: {encrypted_file}")

        # Delete the original compressed file
        os.remove(compressed_file)
        logger.info(f"Original compressed file deleted: {compressed_file}")

        # Create the 'vault' directory if it doesn't exist
        encrypted_dir = "vault"
        os.makedirs(encrypted_dir, exist_ok=True)

        # Move the generated files into the 'vault' directory
        for file in [checksum_file, encrypted_file, encrypted_key_file]:
            destination = os.path.join(encrypted_dir, os.path.basename(file))
            os.rename(file, destination)
            logger.info(f"Moved {file} to {destination}")

    except Exception as e:
        logger.exception("An error occurred during the encryption process.")
        print(f"An error occurred: {e}")

    finally:
        # Cleanup extracted .pem files
        cleanup_pem_files(extract_to)


if __name__ == "__main__":
    main()
