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
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Initialize logger
logger = logging.getLogger(__name__)

class RSAEncryption:
    def __init__(self, private_key_path, public_key_path, private_key_password=None):
        """
        Initialize RSAEncryption with paths to private and public keys.
        :param private_key_path: Path to the private key file.
        :param public_key_path: Path to the public key file.
        :param private_key_password: Password for the private key (if encrypted).
        """
        try:
            self.private_key = self._load_private_key(private_key_path, private_key_password)
            self.public_key = self._load_public_key(public_key_path)
            logger.info("RSA keys successfully loaded.")
        except Exception as e:
            logger.exception("Failed to initialize RSAEncryption.")
            raise

    def _load_private_key(self, private_key_path, password):
        """
        Load the private key from a file.
        :param private_key_path: Path to the private key file.
        :param password: Password for the private key (if encrypted).
        :return: Loaded private key object.
        """
        try:
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode() if password else None,
                    backend=default_backend()
                )
            logger.info(f"Private key loaded from {private_key_path}.")
            return private_key
        except TypeError as e:
            if "Password was not given but private key is encrypted" in str(e):
                logger.error(f"Private key is encrypted but no password was provided: {private_key_path}")
            raise
        except FileNotFoundError:
            logger.error(f"Private key file not found: {private_key_path}")
            raise
        except ValueError as e:
            logger.error(f"Failed to load private key. Invalid password or corrupted file: {private_key_path}")
            raise
        except Exception as e:
            logger.exception(f"An unexpected error occurred while loading the private key: {private_key_path}")
            raise

    def _load_public_key(self, public_key_path):
        """
        Load the public key from a file.
        :param public_key_path: Path to the public key file.
        :return: Loaded public key object.
        """
        try:
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            logger.info(f"Public key loaded from {public_key_path}.")
            return public_key
        except FileNotFoundError:
            logger.error(f"Public key file not found: {public_key_path}")
            raise
        except Exception as e:
            logger.exception(f"An unexpected error occurred while loading the public key: {public_key_path}")
            raise

    def encrypt_key(self, aes_key):
        """
        Encrypt an AES key using the public key.
        :param aes_key: AES key to encrypt.
        :return: Encrypted AES key.
        """
        try:
            encrypted_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.info("AES key successfully encrypted using the public key.")
            return encrypted_key
        except Exception as e:
            logger.exception("Failed to encrypt AES key.")
            raise

    def decrypt_key(self, encrypted_key):
        """
        Decrypt an AES key using the private key.
        :param encrypted_key: Encrypted AES key.
        :return: Decrypted AES key.
        """
        try:
            decrypted_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.info("AES key successfully decrypted using the private key.")
            return decrypted_key
        except Exception as e:
            logger.exception("Failed to decrypt AES key.")
            raise
