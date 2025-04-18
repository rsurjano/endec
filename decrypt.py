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
        # Encuentra el archivo de datos más reciente (data_)
        data_pattern = r'data_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip\.enc'
        encrypted_file = find_latest_file("vault", data_pattern)
        logger.info(f"Archivo de datos más reciente identificado: {encrypted_file}")

        # Extrae el string de fecha del nombre del archivo de datos
        data_date_str = re.search(r'data_(\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})', encrypted_file).group(1)

        # Encuentra el archivo de claves más reciente ({hint}_keys_)
        keys_pattern = r'.*_keys_\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2}\.zip'
        keys_zip_file = find_latest_file("vault", keys_pattern)
        logger.info(f"Archivo de claves más reciente identificado: {keys_zip_file}")

        # Extrae el string de fecha del nombre del archivo de claves
        keys_date_str = re.search(r'keys_(\d{2}_\d{2}_\d{4}_\d{2}_\d{2}_\d{2})', keys_zip_file).group(1)

        # Define las rutas relacionadas
        encrypted_key_file = os.path.join("vault", f'encrypted_aes_key_{data_date_str}.bin')
        checksum_file = os.path.join("vault", f'checksum_{data_date_str}.sha256')

        # Solicita la contraseña para descifrar la clave privada
        password = input("Introduce la contraseña para la clave privada: ").strip()

        # Valida y descomprime el archivo zip de claves para extraer las claves privadas y públicas
        if not extract_pem_files(keys_zip_file, "vault", password):
            logger.error("No se pudieron extraer las claves del archivo zip. Saliendo.")
            return
        logger.info("Claves extraídas exitosamente en el directorio 'vault'.")

        # Define las rutas de las claves privadas y públicas
        private_key_path = os.path.join("vault", f"private_key_{keys_date_str}.pem")
        public_key_path = os.path.join("vault", f"public_key_{keys_date_str}.pem")


        # Carga la clave AES cifrada
        try:
            with open(encrypted_key_file, 'rb') as f:
                encrypted_aes_key = f.read()
            logger.info(f"Clave AES cifrada cargada desde: {encrypted_key_file}")
        except FileNotFoundError:
            logger.error(f"Error: El archivo {encrypted_key_file} no existe.")
            return

        # Carga el checksum
        try:
            with open(checksum_file, 'r') as f:
                original_checksum = f.read().strip()
            logger.info(f"Checksum cargado desde: {checksum_file}")
        except FileNotFoundError:
            logger.error(f"Error: El archivo {checksum_file} no existe.")
            return

        # Inicializa el descifrado RSA
        rsa_encryption = RSAEncryption(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            private_key_password=password
        )

        # Descifra la clave AES
        aes_key = rsa_encryption.decrypt_key(encrypted_aes_key)
        logger.info("Clave AES descifrada exitosamente.")

        # Descifra el archivo cifrado
        AESEncryption.decrypt_file(encrypted_file, aes_key)
        logger.info(f"Archivo cifrado descifrado: {encrypted_file}")

        # Elimina la extensión '.enc' para obtener el archivo ZIP descifrado
        decrypted_file = encrypted_file[:-4]

        # Verifica el checksum del archivo descifrado
        decrypted_checksum = FileChecksum.generate_checksum(decrypted_file)
        if decrypted_checksum == original_checksum:
            logger.info("Verificación de checksum pasada.")
        else:
            logger.error("La verificación de checksum falló.")
            return

        # Descomprime el archivo ZIP descifrado en una carpeta llamada 'data_{date_str}'
        output_folder = f"data_{data_date_str}"
        if os.path.exists(output_folder):
          logger.warning(f"La carpeta de salida '{output_folder}' ya existe. Eliminándola para evitar conflictos.")
          import shutil
          shutil.rmtree(output_folder)
        decompress_folder(decrypted_file, output_folder)
        logger.info(f"Archivo descifrado descomprimido en la carpeta: {output_folder}")

        # Elimina el archivo ZIP descifrado intermedio
        os.remove(decrypted_file)
        logger.info(f"Archivo ZIP descifrado intermedio eliminado: {decrypted_file}")

        # Limpia los archivos .pem extraídos
        cleanup_pem_files("vault")
        logger.info("Archivos .pem extraídos limpiados.")

      except Exception as e:
          logger.exception("Ocurrió un error durante el proceso de descifrado.")
          print(f"Ocurrió un error: {e}")


if __name__ == "__main__":
    decrypt()
