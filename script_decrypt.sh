#!/bin/bash

# Bash script to rehydrate data.zip.enc
# Usage: ./rehydrate.sh <datetime> <password>

# Check if the required arguments are provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <datetime> <password>"
  exit 1
fi

# Arguments
DATETIME=$1
PASSWORD=$2

# Paths
VAULT_DIR="vault"
ENCRYPTED_FILE="${VAULT_DIR}/data_${DATETIME}.zip.enc"
KEYS_ZIP_FILE="${VAULT_DIR}/keys_${DATETIME}.zip"
PRIVATE_KEY_FILE="${VAULT_DIR}/private_key_${DATETIME}.pem"
PUBLIC_KEY_FILE="${VAULT_DIR}/public_key_${DATETIME}.pem"

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

# Decrypt the encrypted file using OpenSSL
echo "Decrypting '$ENCRYPTED_FILE'..."
openssl enc -d -aes-256-cbc -in "$ENCRYPTED_FILE" -out "$DECRYPTED_FILE" -pass file:"$PRIVATE_KEY_FILE"
if [ $? -ne 0 ]; then
  echo "Error: Failed to decrypt the file. Check the private key and try again."
  exit 1
fi
echo "Decryption completed successfully. Decrypted file: $DECRYPTED_FILE"

# Extract the decrypted ZIP file
echo "Extracting decrypted ZIP file..."
unzip -o "$DECRYPTED_FILE" -d "$VAULT_DIR"
if [ $? -ne 0 ]; then
  echo "Error: Failed to extract the decrypted ZIP file."
  exit 1
fi
echo "Extraction completed successfully."

# Cleanup
echo "Cleaning up temporary files..."
rm -f "$DECRYPTED_FILE"
echo "Cleanup completed."

echo "Rehydration process completed successfully."
