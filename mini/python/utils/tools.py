import base64
import datetime
from dataclass import msg
from dataclass import localmsg

LocalMessage = localmsg.LocalMessage
Message = msg.Message

def convert_local_to_message(local_message: LocalMessage) -> Message:
    """
    Converts a LocalMessage object to a Message object.

    Args:
        local_message (LocalMessage): The LocalMessage instance to convert.

    Returns:
        Message: The converted Message instance.
    """
    return Message(
        sender=local_message.sender,
        receiver=local_message.receiver,
        id=local_message.id,
        senderEphemeralPublicKey=local_message.senderEphemeralPublicKey,
        content=base64.b64decode(local_message.content.encode("utf-8")),
        nonce=base64.b64decode(local_message.nonce.encode("utf-8")),
        signature=base64.b64decode(local_message.signature.encode("utf-8")),
        timeBeforeUnlock=datetime.datetime.fromisoformat(local_message.timeBeforeUnlock)
    )
