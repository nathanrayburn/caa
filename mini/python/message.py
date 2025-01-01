import base64
import datetime
import hashlib
import os
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
import server

MESSAGE_FILE = "messages.json"

@dataclass
class User:
    username: str
    hashedPassword: bytes = field(default=None)
    public_key: bytes = field(default=None)
    encrypted_private_key: bytes = field(default=None)
    nonce: bytes = field(default=None)

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
# Function to create the message file if it doesn't exist
def createMessageDB():
    if not os.path.exists(MESSAGE_FILE):
        with open(MESSAGE_FILE, "w") as f:
            json.dump([], f, indent=4)
        print(f"{MESSAGE_FILE} created successfully.")

# Function to load the message database
def loadMessageDB():
    try:
        with open(MESSAGE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {MESSAGE_FILE} not found. Creating a new message database.")
        createMessageDB()
        return []
    except json.JSONDecodeError:
        print(f"Error: {MESSAGE_FILE} is corrupted. Resetting the message database.")
        createMessageDB()
        return []

# Function to save the message database
def saveMessageDB(messages):
    with open(MESSAGE_FILE, "w") as f:
        json.dump(messages, f, indent=4)

# Function to generate the next auto-incremented ID
def getNextMessageID():
    messages = loadMessageDB()
    if not messages:
        return 1  # Start from 1 if no messages exist
    return max(int(message['id']) for message in messages) + 1

def getMessagesByReceiver(username: str):
    # Load the existing messages from the database
    messages = loadMessageDB()

    # Filter messages where the receiver matches the given username
    filtered_messages = [message for message in messages if message['receiver'] == username]

    # Convert the filtered messages back to Message objects
    message_objects = []
    for msg in filtered_messages:
        # Convert the 'timeBeforeUnlock' from string back to datetime
        if 'timeBeforeUnlock' in msg:
            msg['timeBeforeUnlock'] = datetime.datetime.fromisoformat(msg['timeBeforeUnlock'])

        # Convert the 'senderEphemeralPublicKey' from string back to bytes
        if 'senderEphemeralPublicKey' in msg and msg['senderEphemeralPublicKey']:
            msg['senderEphemeralPublicKey'] = msg['senderEphemeralPublicKey'].encode('utf-8')

        # Create the Message object
        message_objects.append(Message(**msg))

    return message_objects

def getMessageByID(message_id: int) -> Optional[Message]:
    # Load the existing messages from the database
    messages = loadMessageDB()

    # Find the message with the given ID
    for msg in messages:
        if int(msg['id']) == message_id:
            # Deserialize 'timeBeforeUnlock' back to datetime
            if 'timeBeforeUnlock' in msg and msg['timeBeforeUnlock']:
                msg['timeBeforeUnlock'] = datetime.datetime.fromisoformat(msg['timeBeforeUnlock'])

            # Convert 'senderEphemeralPublicKey' back to bytes
            if 'senderEphemeralPublicKey' in msg and msg['senderEphemeralPublicKey']:
                msg['senderEphemeralPublicKey'] = msg['senderEphemeralPublicKey'].encode('utf-8')

            # Convert the dictionary to a Message object
            return Message(**msg)

    # If the message is not found, return None
    print(f"No message found with ID {message_id}.")
    return None

# Function to save a message in the message database
def saveMessage(message: Message):
    # Ensure the message database exists
    createMessageDB()

    # Load existing messages
    messages = loadMessageDB()

    # Convert the Message object to a dictionary
    message_dict = asdict(message)

    # Serialize datetime fields
    if isinstance(message_dict.get("timeBeforeUnlock"), datetime.datetime):
        message_dict["timeBeforeUnlock"] = message_dict["timeBeforeUnlock"].isoformat()
    message_dict["senderEphemeralPublicKey"] = message.senderEphemeralPublicKey.decode('utf-8') if message.senderEphemeralPublicKey else None
    # Append the new message to the message list
    messages.append(message_dict)

    # Save the updated message database
    saveMessageDB(messages)
    print(f"Message with ID '{message.id}' saved successfully.")
