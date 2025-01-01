import json
import os
import datetime
import base64
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from dataclass import localmsg


LocalMessage = localmsg.LocalMessage

LOCAL_MESSAGE_FILE = "local_messages.json"



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
                is_decrypted: bool = False, decrypted_content: str = None):
    messages = load_local_messages()
    new_message = LocalMessage.from_message(
        message_id=message_id,
        sender=sender,
        receiver=receiver,
        content=content,
        nonce=nonce,
        signature=signature,
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