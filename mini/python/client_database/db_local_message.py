import json
import os
import datetime
import base64
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from dataclass import localmsg


LocalMessage = localmsg.LocalMessage

LOCAL_MESSAGE_FILE = "local_messages.json"

def get_message_by_id(message_id: int) -> Optional[LocalMessage]:
    """
    Retrieves a message by its ID from the local message database.

    Args:
        message_id (int): The ID of the message to retrieve.

    Returns:
        Optional[LocalMessage]: The message object if found, or None if not found.
    """
    messages = load_local_messages()  # Load all messages from the local database

    for msg in messages:  # Iterate through the messages
        if msg.id == message_id:  # Check if the message ID matches
            return msg  # Return the message if found

    # If the message is not found, return None
    print(f"Message with ID {message_id} not found.")
    return None

def getUndecryptedUnlockedMessageIDs() -> List[int]:
    """
    Retrieves the IDs of messages that have been unlocked (timeBeforeUnlock has passed)
    but have not yet been decrypted.

    Returns:
        List[int]: A list of message IDs.
    """
    current_time = datetime.datetime.now()
    messages = load_local_messages()
    undecrypted_unlocked_ids = [
        msg.id for msg in messages
        if datetime.datetime.fromisoformat(msg.timeBeforeUnlock) <= current_time and not msg.is_decrypted
    ]
    return undecrypted_unlocked_ids

def getAllMessageIDs() -> List[int]:
    messages = load_local_messages()
    return [msg.id for msg in messages]

def create_local_message_db():
    if not os.path.exists(LOCAL_MESSAGE_FILE):
        with open(LOCAL_MESSAGE_FILE, "w") as f:
            json.dump([], f, indent=4)

def load_local_messages() -> List[LocalMessage]:
    try:
        with open(LOCAL_MESSAGE_FILE, "r") as f:
            messages = json.load(f)
            return [LocalMessage(**msg) for msg in messages]
    except (FileNotFoundError, json.JSONDecodeError):
        create_local_message_db()
        return []

def save_local_messages(messages: List[LocalMessage]):
    with open(LOCAL_MESSAGE_FILE, "w") as f:
        json.dump([asdict(msg) for msg in messages], f, indent=4)

def save_message(message_id: int, sender: str, receiver: str, content: str,
                nonce: str, signature: str, timeBeforeUnlock: datetime.datetime,
                is_decrypted: bool = False, decrypted_content: str = None, senderEphemeralPublicKey: str = None):
    messages = load_local_messages()
    new_message = LocalMessage.from_message(
        message_id=message_id,
        sender=sender,
        receiver=receiver,
        content=content,
        nonce=nonce,
        signature=signature,
        senderEphemeralPublicKey=senderEphemeralPublicKey,
        timeBeforeUnlock=timeBeforeUnlock,
        is_decrypted=is_decrypted,
        decrypted_content=decrypted_content
    )
    messages.append(new_message)
    save_local_messages(messages)

def get_local_messages(username: str) -> List[LocalMessage]:
    return [msg for msg in load_local_messages() if msg.receiver == username]

def message_exists_locally(message_id: int) -> bool:
    return any(msg.id == message_id for msg in load_local_messages())

def update_message_content(message_id: int, decrypted_content: str):
    messages = load_local_messages()
    for i, msg in enumerate(messages):
        if msg.id == message_id:
            messages[i].is_decrypted = True
            messages[i].decrypted_content = decrypted_content
            break
    save_local_messages(messages)

def get_locked_messages(username: str) -> List[LocalMessage]:
    current_time = datetime.datetime.now()
    return [msg for msg in load_local_messages()
            if msg.receiver == username and
            datetime.datetime.fromisoformat(msg.timeBeforeUnlock) > current_time]

def get_unlocked_messages(username: str) -> List[LocalMessage]:
    current_time = datetime.datetime.now()
    return [msg for msg in load_local_messages()
            if msg.receiver == username and
            datetime.datetime.fromisoformat(msg.timeBeforeUnlock) <= current_time]