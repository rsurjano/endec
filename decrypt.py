import os
import re
import logging
import hashlib
from utils.aes_encryption import AESEncryption
from utils.rsa_encryption import RSAEncryption
from utils.file_operations import decompress_folder
from logging_config import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


def generate_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def find_latest_encrypted_file():
    pattern = re.compile(r'data_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip\.enc')
    files = [f for f in os.listdir() if os.path.isfile(f) and pattern.match(f)]
    if not files:
        logger.error(
            "No encrypted file matching the pattern 'data_*.zip.enc' found.")
        raise FileNotFoundError(
            "No encrypted file matching the pattern 'data_*.zip.enc' found.")
    latest_file = max(files, key=os.path.getmtime)
    logger.info(f"Latest encrypted file found: {latest_file}")
    return latest_file


def decrypt():
    try:
        encrypted_file = find_latest_encrypted_file()
        logger.info(f"Latest encrypted file identified: {encrypted_file}")
        date_str = re.search(
            r'data_(\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})', encrypted_file).group(1)
    except FileNotFoundError as e:
        logger.error(f"Error finding the latest encrypted file: {e}")
        return

    encrypted_key_file = f'encrypted_aes_key_{date_str}.bin'
    checksum_file = f'checksum_{date_str}.sha256'

    try:
        with open(encrypted_key_file, 'rb') as f:
            encrypted_aes_key = f.read()
        logger.info(f"Encrypted AES key loaded from: {encrypted_key_file}")
    except FileNotFoundError:
        logger.error(f"Error: The file {encrypted_key_file} does not exist.")
        return

    try:
        with open(checksum_file, 'r') as f:
            original_checksum = f.read().strip()
        logger.info(f"Checksum loaded from: {checksum_file}")
    except FileNotFoundError:
        logger.error(f"Error: The file {checksum_file} does not exist.")
        return

    rsa_encryption = RSAEncryption()
    aes_key = rsa_encryption.decrypt_key(encrypted_aes_key)
    logger.info("AES key successfully decrypted.")

    AESEncryption.decrypt_file(encrypted_file, aes_key)
    logger.info(f"Encrypted file decrypted: {encrypted_file}")

    decrypted_file = encrypted_file[:-4]  # Remove the '.enc' extension
    output_folder = 'data'  # Always decompress into 'data' folder
    decompress_folder(decrypted_file, output_folder)
    logger.info(f"Decrypted file decompressed into folder: {output_folder}")

    # Verify checksum
    decrypted_checksum = generate_checksum(decrypted_file)
    if decrypted_checksum == original_checksum:
        logger.info("Checksum verification passed.")
    else:
        logger.error("Checksum verification failed.")

    # Delete the intermediate decrypted ZIP file
    os.remove(decrypted_file)
    logger.info(f"Intermediate decrypted ZIP file deleted: {decrypted_file}")

    # Clean up older encrypted AES key files
    for file in os.listdir():
        if re.match(r'encrypted_aes_key_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.bin', file) and file != encrypted_key_file:
            os.remove(file)
            logger.info(f"Old encrypted AES key file deleted: {file}")


if __name__ == "__main__":
    decrypt()
