import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Generate a new RSA key pair
private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_rsa = private_key_rsa.public_key()

# Serialize the RSA private key and the public key
private_key_rsa_pem = private_key_rsa.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_rsa_pem = public_key_rsa.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Generate a new elliptic curve key pair
private_key_ec = ec.generate_private_key(ec.SECP256K1(), default_backend())
public_key_ec = private_key_ec.public_key()

# Serialize the elliptic curve private key and public key
private_key_ec_pem = private_key_ec.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_ec_pem = public_key_ec.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print the serialized public and private keys
print(f'RSA Private Key PEM:\n{private_key_rsa_pem.decode()}')
print(f'RSA Public Key PEM:\n{public_key_rsa_pem.decode()}')
print(f'EC Private Key PEM:\n{private_key_ec_pem.decode()}')
print(f'EC Public Key PEM:\n{public_key_ec_pem.decode()}')

# Define the message
message = b'The secret message no one should read'

# Encrypt the message using the RSA public key
ciphertext = public_key_rsa.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypting the message using the RSA private key
decrypted_message = private_key_rsa.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Printing the original and decrypted secret message
print(f'Original message: {message.decode()}')
print(f'Decrypted message: {decrypted_message.decode()}')