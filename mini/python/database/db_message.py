import datetime
import json
import os
from dataclasses import asdict
from typing import List, Optional, Dict

from dataclass import user, msg

# Data Models
Message = msg.Message
User = user.User

# Constants
MESSAGE_FILE = "messages.json"


# Helper Functions
def create_message_db():
    """Ensure the message database file exists."""
    if not os.path.exists(MESSAGE_FILE):
        with open(MESSAGE_FILE, "w") as f:
            json.dump([], f, indent=4)
        print(f"{MESSAGE_FILE} created successfully.")


def load_message_db() -> List[Dict]:
    """Load the message database from file."""
    try:
        with open(MESSAGE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {MESSAGE_FILE} not found. Creating a new message database.")
        create_message_db()
        return []
    except json.JSONDecodeError:
        print(f"Error: {MESSAGE_FILE} is corrupted. Resetting the message database.")
        create_message_db()
        return []


def save_message_db(messages: List[Dict]):
    """Save the message database to file."""
    with open(MESSAGE_FILE, "w") as f:
        json.dump(messages, f, indent=4)


def get_next_message_id() -> int:
    """Generate the next auto-incremented message ID."""
    messages = load_message_db()
    return max((int(msg['id']) for msg in messages), default=0) + 1


def deserialize_message(msg: Dict) -> Message:
    """Convert a dictionary to a Message object."""
    if 'timeBeforeUnlock' in msg and msg['timeBeforeUnlock']:
        msg['timeBeforeUnlock'] = datetime.datetime.fromisoformat(msg['timeBeforeUnlock'])
    if 'senderEphemeralPublicKey' in msg and msg['senderEphemeralPublicKey']:
        msg['senderEphemeralPublicKey'] = msg['senderEphemeralPublicKey'].encode('utf-8')
    return Message(**msg)


def serialize_message(message: Message) -> Dict:
    """Convert a Message object to a dictionary, serializing datetime fields."""
    msg_dict = asdict(message)
    if isinstance(msg_dict.get("timeBeforeUnlock"), datetime.datetime):
        msg_dict["timeBeforeUnlock"] = msg_dict["timeBeforeUnlock"].isoformat()
    msg_dict["senderEphemeralPublicKey"] = (
        message.senderEphemeralPublicKey.decode('utf-8') if message.senderEphemeralPublicKey else None
    )
    return msg_dict


# Core Database Functions
def get_messages_by_receiver(username: str) -> List[Message]:
    """Get messages where the receiver matches the given username."""
    messages = load_message_db()
    filtered_messages = [deserialize_message(msg) for msg in messages if msg['receiver'] == username]
    return filtered_messages


def get_new_messages(username: str, id_messages: List[int]) -> List[Message]:
    """Retrieve new messages for the user that are not already downloaded."""
    user_messages = get_messages_by_receiver(username)
    return [msg for msg in user_messages if msg.id not in id_messages]


def get_message_by_id(message_id: int) -> Optional[Message]:
    """Retrieve a specific message by its ID."""
    messages = load_message_db()
    for msg in messages:
        if int(msg['id']) == message_id:
            return deserialize_message(msg)
    print(f"No message found with ID {message_id}.")
    return None


def get_ephemeral_public_keys(message_ids: List[int]) -> Dict[int, Optional[bytes]]:
    """Retrieve the senderEphemeralPublicKey for each message ID."""
    messages = load_message_db()
    ephemeral_keys = {}
    for msg in messages:
        if int(msg['id']) in message_ids:
            ephemeral_key = msg.get('senderEphemeralPublicKey')
            ephemeral_keys[int(msg['id'])] = ephemeral_key.encode('utf-8') if ephemeral_key else None
    return ephemeral_keys


def save_message(message: Message):
    """Save a new message to the database."""
    create_message_db()
    messages = load_message_db()
    messages.append(serialize_message(message))
    save_message_db(messages)
    print(f"Message with ID '{message.id}' saved successfully.")
