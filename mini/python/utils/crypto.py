import hashlib
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from dataclass import user
from dataclass import msg

Message = msg.Message
User = user.User

def hashUserKey(userkey):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"serverkey-salt",
        backend=default_backend()
    )
    return hkdf.derive(userkey)

# Hash a password using Argon2id
def deriveUserKeyFromPassword(username, password):
    salt = deriveSaltFromUsername(username)

    # Derive the raw hash/key using Argon2id
    user_key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,  # Time cost parameter (adjust as needed)
        memory_cost=2**16,  # Memory cost parameter in kibibytes
        parallelism=1,  # Parallelism factor
        hash_len=32,  # Length of the resulting hash/key
        type=Type.ID  # Argon2id (preferred for password hashing)
    )
    return user_key

# Generate a salt using HKDF and the username
def deriveSaltFromUsername(username):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"username-salt",
        backend=default_backend()
    )
    return hkdf.derive(username.encode())

def encryptPrivateKey(userkey, privateKey):
    chacha = ChaCha20Poly1305(userkey)
    nonce = os.urandom(12)
    cipheredPrivateKey = chacha.encrypt(nonce, privateKey, None)
    return cipheredPrivateKey, nonce

def decryptPrivateKey(userkey, ct, nonce):
    chacha = ChaCha20Poly1305(userkey)
    return chacha.decrypt(nonce, ct, None)

def generate_identity_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Generate an ephemeral key pair (new for each message)
def generate_ephemeral_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret
def export_private_key_to_bytes(private_key):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # or DER
        format=serialization.PrivateFormat.PKCS8,  # Standard format for private keys
        encryption_algorithm=serialization.NoEncryption()  # No password protection
    )
    return private_key_bytes
def export_public_key_to_bytes(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # or DER
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard format for public keys
    )
    return public_key_bytes

def import_private_key_from_bytes(private_key_bytes):
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,  # Add password if the key is encrypted
        backend=default_backend()
    )
    return private_key
def import_public_key_from_bytes(public_key_bytes):
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key

# Encrypt a message
def encrypt_message(encryption_key, plaintext):
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = ChaCha20Poly1305(encryption_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

# Decrypt a message
def decrypt_message(encryption_key, nonce, ciphertext):
    cipher = ChaCha20Poly1305(encryption_key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext

def derive_encryption_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit encryption key
        salt=None,  # Optionally, include a salt
        info=b"dh-ratchet",  # Context-specific info
        backend=default_backend()
    )
    encryption_key = hkdf.derive(shared_secret)
    return encryption_key

def sender_workflow(receiver_public_key, plaintext):
    # Generate ephemeral key pair for this message
    sender_private_key, sender_public_key = generate_ephemeral_keypair()

    # Compute shared secret
    shared_secret = compute_shared_secret(sender_private_key, receiver_public_key)

    # Derive encryption key
    encryption_key = derive_encryption_key(shared_secret)

    # Encrypt the message
    nonce, ciphertext = encrypt_message(encryption_key, plaintext)

    # Send: sender_public_key, nonce, ciphertext
    return sender_public_key, nonce, ciphertext

def receiver_workflow(receiver_private_key, sender_public_key, nonce, ciphertext):
    # Compute shared secret
    shared_secret = compute_shared_secret(receiver_private_key, sender_public_key)
    # Derive encryption key
    encryption_key = derive_encryption_key(shared_secret)
    # Decrypt the message
    plaintext = decrypt_message(encryption_key, nonce, ciphertext)
    return plaintext

# Function to hash the password using SHA3
def hashPassword(password: bytes) -> bytes:

    sha3_hasher = hashlib.sha3_512()
    sha3_hasher.update(password)
    return sha3_hasher.digest()
