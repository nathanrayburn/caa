import base64
from dataclasses import dataclass, field

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

