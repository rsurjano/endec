import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


class AESEncryption:
    @staticmethod
    def generate_key():
        return os.urandom(32)  # Clave AES de 256 bits

    @staticmethod
    def generate_iv():
        return os.urandom(16)  # Vector de inicialización de 128 bits

    @staticmethod
    def encrypt_file(file_path, aes_key, iv):
        with open(file_path, 'rb') as f:
            data = f.read()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path + '.enc', 'wb') as f:
            f.write(iv + encrypted_data)

    @staticmethod
    def decrypt_file(file_path, aes_key):
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            encrypted_data = f.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(file_path[:-4], 'wb') as f:
            f.write(data)
