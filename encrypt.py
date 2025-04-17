import os
import re
import logging
import hashlib
from datetime import datetime
from encryption.aes_encryption import AESEncryption
from encryption.rsa_encryption import RSAEncryption
from encryption.file_operations import compress_folder, git_commit
from logging_config import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


def find_latest_data_folder():
    pattern1 = re.compile(r'data_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}')
    pattern2 = re.compile(r'data')
    folders = [f for f in os.listdir() if os.path.isdir(
        f) and (pattern1.match(f) or pattern2.match(f))]
    if not folders:
        logger.error(
            "No folder matching the patterns 'data' or 'data_dd_mm_yyyy_HH_MM_SS' found.")
        raise FileNotFoundError(
            "No folder matching the patterns 'data' or 'data_dd_mm_yyyy_HH_MM_SS' found.")
    latest_folder = max(folders, key=os.path.getmtime)
    logger.info(f"Latest data folder found: {latest_folder}")
    return latest_folder


def generate_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def main():
    try:
        folder_path = find_latest_data_folder()
    except FileNotFoundError as e:
        logger.error(f"Error finding the latest data folder: {e}")
        return

    date_str = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
    compressed_file = f'data_{date_str}.zip'
    aes_key = AESEncryption.generate_key()  # Generate AES key
    iv = AESEncryption.generate_iv()        # Generate initialization vector

    logger.info(f"Compressing folder: {folder_path}")
    compress_folder(folder_path, compressed_file[:-4], compression='store')
    logger.info(f"Folder compressed into: {compressed_file}")

    # Generate checksum for the original ZIP file
    checksum = generate_checksum(compressed_file)
    with open(f'checksum_{date_str}.sha256', 'w') as f:
        f.write(checksum)
    logger.info(
        f"Checksum generated and stored in: checksum_{date_str}.sha256")

    rsa_encryption = RSAEncryption()
    encrypted_aes_key = rsa_encryption.encrypt_key(aes_key)

    with open(f'encrypted_aes_key_{date_str}.bin', 'wb') as f:
        f.write(encrypted_aes_key)
    logger.info(
        f"Encrypted AES key stored in: encrypted_aes_key_{date_str}.bin")

    AESEncryption.encrypt_file(compressed_file, aes_key, iv)
    logger.info(f"Compressed file encrypted into: {compressed_file}.enc")

    # Delete the original ZIP file
    os.remove(compressed_file)
    logger.info(f"Original ZIP file deleted: {compressed_file}")

    # Clean up older files
    for file in os.listdir():
        # Delete older encrypted AES key files
        if re.match(r'encrypted_aes_key_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.bin', file) and file != f'encrypted_aes_key_{date_str}.bin':
            os.remove(file)
            logger.info(f"Old encrypted AES key file deleted: {file}")

        # Delete older .zip.enc files
        if re.match(r'data_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip\.enc', file) and file != f'data_{date_str}.zip.enc':
            os.remove(file)
            logger.info(f"Old encrypted .zip.enc file deleted: {file}")

        # Delete older checksum files
        if re.match(r'checksum_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.sha256', file) and file != f'checksum_{date_str}.sha256':
            os.remove(file)
            logger.info(f"Old checksum file deleted: {file}")

    # Delete all data* folders
    for folder in os.listdir():
        if os.path.isdir(folder) and re.match(r'data(_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})?', folder):
            try:
                os.rmdir(folder)
                logger.info(f"Data folder deleted: {folder}")
            except OSError:
                logger.warning(f"Failed to delete folder: {folder}")

    git_commit(compressed_file + '.enc', date_str)
    git_commit(f'encrypted_aes_key_{date_str}.bin', date_str)
    git_commit(f'checksum_{date_str}.sha256', date_str)
    logger.info("All files committed to Git successfully.")


if __name__ == "__main__":
    main()
