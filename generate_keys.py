from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


def generate_keys():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Generate RSA public key
    public_key = private_key.public_key()

    # Serialize the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Ensure the keys directory exists
    os.makedirs('keys', exist_ok=True)

    # Save the private key
    with open('keys/private_key.pem', 'wb') as f:
        f.write(private_pem)

    # Save the public key
    with open('keys/public_key.pem', 'wb') as f:
        f.write(public_pem)

    print("RSA keys generated and saved to 'keys' directory.")


if __name__ == "__main__":
    generate_keys()
