from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import pyzipper
import getpass
import logging
from logging_config import setup_logging
from datetime import datetime

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)


class RSAKeyGenerator:
    """Class to handle RSA key generation and storage."""

    def __init__(self, key_size=4096, output_dir="keys"):
        self.key_size = key_size
        self.output_dir = output_dir
        self.private_key = None
        self.public_key = None
        logger.debug(f"Initialized RSAKeyGenerator with key_size={key_size}, output_dir='{output_dir}'")

    def generate_keys(self):
        """Generate RSA private and public keys."""
        logger.info("Generating RSA keys...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        logger.info("RSA keys generated successfully.")

    def serialize_key(self, key, is_private=True, password=None):
        """Serialize a key (private or public) to PEM format."""
        logger.debug(f"Serializing {'private' if is_private else 'public'} key...")
        if is_private:
            encryption = (
                serialization.BestAvailableEncryption(password.encode())
                if password else serialization.NoEncryption()
            )
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            )
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def save_key(self, key_data, filename):
        """Save a key to a file."""
        os.makedirs(self.output_dir, exist_ok=True)
        file_path = os.path.join(self.output_dir, filename)
        logger.info(f"Saving key to '{file_path}'...")
        with open(file_path, 'wb') as f:
            f.write(key_data)
        logger.info(f"Key saved to '{file_path}'.")
        return file_path

    def save_keys(self, password, date_str):
        """Save both private and public keys to files."""
        if not self.private_key or not self.public_key:
            logger.error("Keys have not been generated yet.")
            raise ValueError("Keys have not been generated yet.")
        private_key_path = self.save_key(
            self.serialize_key(self.private_key, is_private=True, password=password),
            f"private_key_{date_str}.pem"
        )
        public_key_path = self.save_key(
            self.serialize_key(self.public_key, is_private=False),
            f"public_key_{date_str}.pem"
        )
        return private_key_path, public_key_path


class SecureKeyStorage:
    """Class to handle secure storage of keys in an encrypted compressed file."""

    def __init__(self, output_dir="keys", archive_name=None):
        self.output_dir = output_dir
        self.archive_name = archive_name
        logger.debug(f"Initialized SecureKeyStorage with output_dir='{output_dir}', archive_name='{archive_name}'")

    def compress_and_encrypt(self, files, password):
        """Compress and encrypt files into a single archive."""
        archive_path = os.path.join(self.output_dir, self.archive_name)
        logger.info(f"Compressing and encrypting files into '{archive_path}'...")
        with pyzipper.AESZipFile(archive_path, 'w', compression=pyzipper.ZIP_DEFLATED) as zf:
            zf.setpassword(password.encode())
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            for file in files:
                logger.debug(f"Adding '{file}' to archive...")
                zf.write(file, os.path.basename(file))
        logger.info(f"Files compressed and encrypted into '{archive_path}'.")
        return archive_path

    def cleanup_files(self, files):
        """Remove the original files after compression."""
        logger.info("Cleaning up original PEM files...")
        for file in files:
            if os.path.exists(file):
                logger.debug(f"Removing file '{file}'...")
                os.remove(file)
        logger.info("Cleanup completed.")


def main():
    """Main function to generate, save, and securely store RSA keys."""
    try:
        # Generate a timestamp for file naming
        date_str = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")

        # Prompt user for a password to encrypt the private key and archive
        password = getpass.getpass("Enter a password to secure your keys: ")
        if not password:
            logger.error("Password cannot be empty. Exiting.")
            print("Password cannot be empty. Exiting.")
            return

        # Generate RSA keys
        key_generator = RSAKeyGenerator()
        key_generator.generate_keys()
        private_key_path, public_key_path = key_generator.save_keys(password, date_str)

        # Securely store keys in an encrypted compressed file
        archive_name = f"keys_{date_str}.zip"
        secure_storage = SecureKeyStorage(archive_name=archive_name)
        archive_path = secure_storage.compress_and_encrypt(
            [private_key_path, public_key_path],
            password
        )

        # Cleanup PEM files
        secure_storage.cleanup_files([private_key_path, public_key_path])

        logger.info(f"Keys securely stored in '{archive_path}' and PEM files removed.")
        print(f"Keys securely stored in '{archive_path}' and PEM files removed.")
    except Exception as e:
        logger.exception("An error occurred during key generation or storage.")
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
