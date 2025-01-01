import datetime
from dataclasses import dataclass, field

@dataclass
class LocalMessage:
    id: int
    sender: str
    receiver: str
    content: str   # base64 encoded bytes
    nonce: str     # base64 encoded bytes
    signature: str # base64 encoded bytes
    senderEphemeralPublicKey: str
    timeBeforeUnlock: str  # ISO format string
    is_decrypted: bool = False
    decrypted_content: str = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    @classmethod
    def from_message(cls, message_id: int, sender: str, receiver: str, content: str,
                    nonce: str, signature: str, timeBeforeUnlock: str, is_decrypted: bool = False,
                    decrypted_content: str = None, senderEphemeralPublicKey : str = None):
        return cls(
            id=message_id,
            sender=sender,
            receiver=receiver,
            content=content,
            nonce=nonce,
            signature=signature,
            senderEphemeralPublicKey = senderEphemeralPublicKey,
            timeBeforeUnlock=timeBeforeUnlock,
            is_decrypted=is_decrypted,
            decrypted_content=decrypted_content
        )

    def get_unlock_time(self) -> datetime.datetime:
        return datetime.datetime.fromisoformat(self.timeBeforeUnlock)