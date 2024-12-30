import json
import getpass
import os
import base64
import server

from argon2.low_level import hash_secret, Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import rsa
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

    # Method to decode the nonce
    def getNonce(self) -> bytes:
        return base64.b64decode(self.nonce.decode("utf-8"))

    # Method to decode the encrypted private key
    def getEncryptedPrivateKey(self) -> bytes:
        return base64.b64decode(self.encrypted_private_key.decode("utf-8"))

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

def getUsername():
    return "username"
def getPassword():
    return "password"


def keyGeneration():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used value
        key_size=2048  # Key size in bits
    )

    # Serialize the private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    # Serialize the public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def registerClient():
    # get username input
    username = getUsername()
    # get password input
    password = getPassword()
    # generate keys
    private_key, public_key = keyGeneration()
    print("PRIV/PUB:", private_key, public_key)

    userkey = deriveUserKeyFromPassword(username, password)
    print("Userkey:", userkey)
    hasheduserkey = hashUserKey(userkey)

    # Encrypt private key
    encryptedprivatekey, nonce = encryptPrivateKey(userkey, private_key)

    print(f"Encrypted Private Key{encryptedprivatekey}")

    # register to server
    server.register(username, hasheduserkey, public_key, encryptedprivatekey, nonce)

def loginClient():

    username = getUsername()

    password = getPassword()

    userkey = deriveUserKeyFromPassword(username, password)

    hasheduserkey = hashUserKey(userkey)

    return server.login(username, hasheduserkey), userkey


def sendMessage():
    return 1

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
                logged_menu(user)
            else:
                print("TA MERE LA PUTE")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

def logged_menu(user):
    while True:
        print("\n=== Logged Menu ===")
        print("1. Send message")
        print("2. Modify password")
        print("3. Logout")
        choice = input("Choose an option: ")
        if choice == "1":
            sendMessage()
        elif choice == "2":
            userkey = deriveUserKeyFromPassword("username", "password")
            hashedPassword = hashUserKey(userkey)
            private_key = decryptPrivateKey(userkey, User.getEncryptedPrivateKey(user), User.getNonce(user))

            newUserkey = deriveUserKeyFromPassword("username", "new_password")
            newHashedUserkey = hashUserKey(newUserkey)

            new_encrypted_private_key, nonce = encryptPrivateKey(newUserkey, private_key)

            user = server.modifyPassword(user.username, hashedPassword, new_encrypted_private_key, nonce, newHashedUserkey)

main()