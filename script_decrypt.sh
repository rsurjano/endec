#!/bin/bash

# Bash script to rehydrate data.zip.enc
# Usage: ./rehydrate.sh <encrypted_datetime> <key_datetime> <password>

# Check if the required arguments are provided
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <encrypted_datetime> <key_datetime> <password>"
  exit 1
fi

# Arguments
ENCRYPTED_DATETIME=$1
KEY_DATETIME=$2
PASSWORD=$3

VAULT_DIR="vault"

# Dynamically find the keys zip file based on KEY_DATETIME
KEYS_ZIP_FILE=$(find "$VAULT_DIR" -type f -name "${KEY_DATETIME}_*keys.zip" | head -n 1)

# Check if the keys zip file exists
if [ -z "$KEYS_ZIP_FILE" ]; then
  echo "Error: Keys zip file for datetime '$KEY_DATETIME' not found in '$VAULT_DIR'."
  exit 1
fi
ENCRYPTED_FILE="${VAULT_DIR}/${ENCRYPTED_DATETIME}_data.zip.enc"
PRIVATE_KEY_FILE="${VAULT_DIR}/private_key_${KEY_DATETIME}.pem"
PUBLIC_KEY_FILE="${VAULT_DIR}/public_key_${KEY_DATETIME}.pem"
ENCRYPTED_AES_KEY_FILE="${VAULT_DIR}/${ENCRYPTED_DATETIME}_encrypted_aes_key.bin"
CHECKSUM_FILE="${VAULT_DIR}/${ENCRYPTED_DATETIME}_checksum.sha256"
DECRYPTED_FILE="${VAULT_DIR}/${ENCRYPTED_DATETIME}_decrypted_data.zip"
OUTPUT_FOLDER="${VAULT_DIR}/${ENCRYPTED_DATETIME}_data"
AES_KEY_FILE="${VAULT_DIR}/aes_key.bin"

# Check if the encrypted file exists
if [ ! -f "$ENCRYPTED_FILE" ]; then
  echo "Error: Encrypted file '$ENCRYPTED_FILE' not found."
  exit 1
fi

# Check if the keys zip file exists
if [ ! -f "$KEYS_ZIP_FILE" ]; then
  echo "Error: Keys zip file '$KEYS_ZIP_FILE' not found."
  exit 1
fi

# Extract the keys using 7z
echo "Extracting keys from '$KEYS_ZIP_FILE'..."
7z x -p"$PASSWORD" -o"$VAULT_DIR" "$KEYS_ZIP_FILE"
if [ $? -ne 0 ]; then
  echo "Error: Failed to extract keys. Check the password and try again."
  exit 1
fi
echo "Keys extracted successfully."

# Check if the private and public keys exist
if [ ! -f "$PRIVATE_KEY_FILE" ] || [ ! -f "$PUBLIC_KEY_FILE" ]; then
  echo "Error: Private or public key not found in '$VAULT_DIR'."
  exit 1
fi

# Decrypt the AES key using the private key
echo "Decrypting AES key..."
openssl pkeyutl -decrypt -inkey "$PRIVATE_KEY_FILE" -in "$ENCRYPTED_AES_KEY_FILE" -out "$AES_KEY_FILE" -passin pass:"$PASSWORD"
if [ $? -ne 0 ]; then
  echo "Error: Failed to decrypt the AES key. Check the private key and passphrase."
  exit 1
fi
echo "AES key decrypted successfully."

# Decrypt the encrypted file using the AES key
echo "Decrypting '$ENCRYPTED_FILE'..."
openssl enc -d -aes-256-cbc -in "$ENCRYPTED_FILE" -out "$DECRYPTED_FILE" -pass file:"$AES_KEY_FILE"
if [ $? -ne 0 ]; then
  echo "Error: Failed to decrypt the file. Check the AES key and try again."
  exit 1
fi
echo "Decryption completed successfully. Decrypted file: $DECRYPTED_FILE"

# Validate the checksum of the decrypted file
echo "Validating checksum..."
DECRYPTED_CHECKSUM=$(shasum -a 256 "$DECRYPTED_FILE" | awk '{print $1}')
ORIGINAL_CHECKSUM=$(cat "$CHECKSUM_FILE")
if [ "$DECRYPTED_CHECKSUM" != "$ORIGINAL_CHECKSUM" ]; then
  echo "Error: Checksum validation failed. The decrypted file may be corrupted."
  exit 1
fi
echo "Checksum validation passed."

# Extract the decrypted ZIP file
echo "Extracting decrypted ZIP file..."
unzip -o "$DECRYPTED_FILE" -d "$OUTPUT_FOLDER"
if [ $? -ne 0 ]; then
  echo "Error: Failed to extract the decrypted ZIP file."
  exit 1
fi
echo "Extraction completed successfully. Output folder: $OUTPUT_FOLDER"

# Cleanup
echo "Cleaning up temporary files..."
rm -f "$DECRYPTED_FILE" "$AES_KEY_FILE"
echo "Cleanup completed."

echo "Rehydration process completed successfully."
