import json
import getpass
import os
import base64
from typing import List

from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

import server
import message
import datetime

from argon2.low_level import hash_secret, Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
# Configuration
# Initialize the Argon2 password hasher
argon2_hasher = PasswordHasher()



@dataclass
class User:
    username: str
    hashedPassword: bytes = field(default=None)
    public_key: bytes = field(default=None)
    encrypted_private_key: bytes = field(default=None)
    nonce: bytes = field(default=None)
    userKey: bytes = field(default=None)
    # Method to decode the nonce
    def getNonce(self) -> bytes:
        return base64.b64decode(self.nonce.decode("utf-8"))

    # Method to decode the encrypted private key
    def getEncryptedPrivateKey(self) -> bytes:
        return base64.b64decode(self.encrypted_private_key.decode("utf-8"))
@dataclass
class Message:
    sender: str
    receiver: str
    id: int = field(default=None)
    senderEphemeralPublicKey: bytes = field(default=None)
    content: str = field(default=None)
    nonce: bytes = field(default=None)
    timeBeforeUnlock: datetime = field(default=None)
    def getNonce(self) -> bytes:
        return base64.b64decode(self.nonce.encode("utf-8"))
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

def registerClient():
    # get username input
    username = input("Choose your username: ")
    # get password input
    password = input("Choose your password: ")
    # generate keys
    private_key, public_key = generate_identity_keypair()
    private_key_bytes = export_private_key_to_bytes(private_key)

    public_key_bytes = export_public_key_to_bytes(public_key)
    userkey = deriveUserKeyFromPassword(username, password)

    hasheduserkey = hashUserKey(userkey)

    # Encrypt private key
    encryptedprivatekey, nonce = encryptPrivateKey(userkey, private_key_bytes)

    # register to server
    server.register(username, hasheduserkey, public_key_bytes, encryptedprivatekey, nonce)

def loginClient():

    username = input("Enter your username: ")

    password = input("Enter your password: ")

    userkey = deriveUserKeyFromPassword(username, password)

    hasheduserkey = hashUserKey(userkey)

    return server.login(username, hasheduserkey), userkey


def get_time_before_unlock():
    while True:
        time_input = input("Enter the time before unlock (YYYY-MM-DDTHH:MM:SS): ")
        try:
            # Parse the input using ISO 8601 format
            time_obj = datetime.datetime.fromisoformat(time_input)
            return time_obj
        except ValueError:
            print("Invalid format. Please use YYYY-MM-DDTHH:MM:SS (e.g., 2024-12-31T12:00:00).")




def main():
    #registerClient()
    #user, userkey = loginClient()
    #encrypted_private_key = base64.b64decode(user.encrypted_private_key.decode('utf-8'))
    #nonce = base64.b64decode(user.nonce.decode("utf-8"))
    # Test login
    #user, userkey = loginClient()
    main_menu()

def main_menu():
    user = None
    while True:
        print("\n=== Main Menu ===")
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        print("=================\n")
        choice = input("Choose an option: ")

        if choice == "1":
            registerClient()
        elif choice == "2":
            user, userkey = loginClient()
            if user:
                user.userKey = userkey
                logged_menu(user)
            else:
                print("TA MERE LA PUTE")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
def sendMessageToUser(sender : User, receiverUsername, plaintext, timeBeforeUnlock : datetime):

    # Get receiver public key
    if sender.username == receiverUsername:
        print("Cannot send message to yourself!")
        return
    receiver_public_key_bytes = server.getUserPublicKey(receiverUsername)

    receiver_public_key = import_public_key_from_bytes(receiver_public_key_bytes)

    sender_ephemeral_key, nonce, ciphertext = sender_workflow(receiver_public_key, plaintext)

    print(ciphertext)
    b64_nonce = base64.b64encode(nonce).decode('utf-8')
    # Create message with given date
    message = Message(sender=sender.username, receiver=receiverUsername, senderEphemeralPublicKey=export_public_key_to_bytes(sender_ephemeral_key), nonce=b64_nonce, timeBeforeUnlock=timeBeforeUnlock)
    # Store into server
    server.sendMessage(sender, message)
    print("Message sent to server.")

def getMyMessages(user : User):
    messages: List[Message] = server.getUserUnlockedMessages(user.username, user.hashedPassword)
    if messages == None:
        print("No messages found.")
        return
    # Process each Message object
    for message in messages:
        # Calculate encryption key and process the message
        nonce = Message.getNonce(message)

        decryptedmessage = receiveMessageFromUser(user, message.content, nonce, message.senderEphemeralPublicKey)
        print(decryptedmessage)
def receiveMessageFromUser(receiver : User, ciphertext, nonce, sender_ephemeral_key):
    receiver_private_key_bytes = decryptPrivateKey(receiver.userKey, receiver.encrypted_private_key, receiver.nonce)
    receiver_private_key = import_private_key_from_bytes(receiver_private_key_bytes)
    # Receiver decrypts the message
    decrypted_message = receiver_workflow(receiver_private_key, sender_ephemeral_key, nonce, ciphertext)
    print("Decrypted message:", decrypted_message)
    return decrypted_message
def logged_menu(user):
    while True:
        print("\n=== Logged Menu ===")
        print("1. Send message")
        print("2. Get my messages")
        print("3. Modify password")
        print("4. Logout")
        choice = input("Choose an option: ")
        if choice == "1":
            content = input("Enter your message: ")
            receiver = input("Enter your receiver: ")
            timebeforeunlock = get_time_before_unlock()
            content_bytes = content.encode('utf-8')
            sendMessageToUser(user, receiver, content_bytes, timebeforeunlock)
        elif choice == "2":
            getMyMessages(user)
        elif choice == "3":
            password = input("Enter your old password: ")
            userkey = deriveUserKeyFromPassword(user.username, password)
            hashedPassword = hashUserKey(userkey)
            private_key = decryptPrivateKey(userkey, User.getEncryptedPrivateKey(user), User.getNonce(user))

            new_password = input("Enter your new password: ")
            newUserkey = deriveUserKeyFromPassword(user.username, new_password)
            newHashedUserkey = hashUserKey(newUserkey)

            new_encrypted_private_key, nonce = encryptPrivateKey(newUserkey, private_key)

            user = server.modifyPassword(user.username, hashedPassword, new_encrypted_private_key, nonce, newHashedUserkey)
        elif choice == "4":
            print("Goodbye!")
            break
main()