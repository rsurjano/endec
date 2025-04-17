# Encryption Script

This project provides scripts to generate RSA keys, compress and encrypt a folder, and then commit the encrypted file to a Git repository.

## Usage

1. Ensure you have Python and the required libraries installed.
2. Generate the RSA keys by running the `generate_keys.py` script.

```sh
python generate_keys.py

python decrypt.py

python encrypt.py


```

requires:

- data_*.zip.enc
- checksum_*.sha256
- encrypted_aes_key_*.bin

and  private_key and public_key files. which can generate from generate_keys.py script

extracted folder will be on /data
