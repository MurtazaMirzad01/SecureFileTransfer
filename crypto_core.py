import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================================
# 1. RSA ASYMMETRIC KEY MANAGEMENT (2048-bit)
# ==========================================
def generate_rsa_keys(username):
    """Generates RSA key pair and writes them locally as PEM files."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{username}_private.pem", "wb") as f:
        f.write(private_pem)

    # Save Public Key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{username}_public.pem", "wb") as f:
        f.write(public_pem)


def load_private_key(username):
    with open(f"{username}_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(username):
    with open(f"{username}_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ==========================================
# 2. AES SYMMETRIC ENCRYPTION (AES-256 GCM)
# ==========================================
def encrypt_file_aes(file_bytes):
    """Encrypts raw byte data using a new random AES-256 Session Key."""
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 12 bytes nonce for GCM mode
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    return aes_key, nonce, ciphertext


def decrypt_file_aes(ciphertext, aes_key, nonce):
    """Decrypts ciphertext using the session key and validation nonce."""
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ==========================================
# 3. DATA INTEGRITY & SIGNATURES (SHA-256 & RSA)
# ==========================================
def calculate_sha256(data_bytes):
    """Generates standard SHA-256 text checksum string."""
    return hashlib.sha256(data_bytes).hexdigest()


def sign_data(private_key, data_bytes):
    """Signs data (like a hash) using the sender's Private Key."""
    return private_key.sign(
        data_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def verify_signature(public_key, data_bytes, signature_bytes):
    """Validates if data matches sender signature using their Public Key."""
    try:
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ==========================================
# 4. KEY ENVELOPING (RSA Encrypting the AES Key)
# ==========================================
def encrypt_aes_key(recipient_public_key, aes_key):
    """Encrypts symmetric AES session key using Bob's RSA public key."""
    return recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def decrypt_aes_key(recipient_private_key, encrypted_aes_key):
    """Decrypts symmetric AES session key using Bob's RSA private key."""
    return recipient_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )