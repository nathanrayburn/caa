import base64
import datetime
from dataclasses import dataclass, field


@dataclass
class Message:
    sender: str
    receiver: str
    id: int = field(default=None)
    senderEphemeralPublicKey: bytes = field(default=None)
    content: bytes = field(default=None)
    nonce: bytes = field(default=None)
    signature: bytes = field(default=None)
    timeBeforeUnlock: datetime = field(default=None)
    def getNonce(self) -> bytes:
        return base64.b64decode(self.nonce.encode("utf-8"))
    def getContent(self) -> bytes:
        return base64.b64decode(self.content.encode("utf-8"))
    def getSignature(self) -> bytes:
        return base64.b64decode(self.signature.encode("utf-8"))