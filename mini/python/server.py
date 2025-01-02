import base64
import datetime
from dataclasses import asdict
from typing import List
from dataclass import user
from dataclass import msg
from utils import crypto

from database import db_user, db_message
from database import db_message

User = user.User
Message = msg.Message



def getUserMessages(username : str, password : str):

    current_time = datetime.datetime.now()
    messages: List[Message] = db_message.get_messages_by_receiver(username)

    unlocked_messages = [msg for msg in messages if msg.timeBeforeUnlock <= current_time]
    locked_messages = [msg for msg in messages if msg.timeBeforeUnlock > current_time]
    # remove the public key so the user can't decrypt since it's still locked
    for msg in locked_messages:
        msg.senderEphemeralPublicKey = None

    return unlocked_messages, locked_messages

def getEphemeralKeysByMessageID(id : int):
    _message = db_message.get_message_by_id(id)
    current_time = datetime.datetime.now()
    if _message.timeBeforeUnlock <= current_time:
        return _message.senderEphemeralPublicKey
    else:
        return None
# Need to check that the user is logged in
def getUserUnlockedMessages(username : str, password : str):

    messages: List[Message] = db_message.get_messages_by_receiver(username)
    # Get the current time to filter the unlocked messages
    current_time = datetime.datetime.now()

    # Filter messages that are unlocked (i.e., timeBeforeUnlock has passed)
    unlocked_messages = [msg for msg in messages if msg.timeBeforeUnlock <= current_time]

    # Return only the unlocked messages
    return unlocked_messages

def getUserPublicKey(username: str) -> bytes:
    user = db_user.findUserInDB(username)
    if user is None:
        return None
    return user.public_key

# Register
def register(username, password, publicKey, cipheredPrivateKey, nonce):
    # Check if user exists
    userInDB = db_user.findUserInDB(username)
    hashedPassword = crypto.hashPassword(password)
    b64_ct = base64.b64encode(cipheredPrivateKey).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')
    if userInDB is None:
        db_user.createUserInDB(User(
            username=username,
            hashedPassword=hashedPassword,
            public_key=publicKey,
            encrypted_private_key=b64_ct,
            nonce=b64_nonce
        ))
        print(f"User '{username}' registered successfully.")
    else:
        print(f"User '{username}' already exists.")


# Login
def login(username, password):
    user = db_user.findUserInDB(username)
    if not user:
        print("User not found.")
        return False

    # Hash the provided password
    hashedInputPassword = crypto.hashPassword(password)

    # Compare the stored hashed password with the hashed input password
    if user.hashedPassword == hashedInputPassword:
        print("Login successful.")
        return user
    else:
        print("Invalid credentials.")
        return False

# Change password
# Function to modify a user's password A VERIFIER
def modifyPassword(username: str, old_password: bytes, new_encrypted_private_key, nonce, new_password: bytes):
    # Ensure the database exists
    db_user.createDB()
    # Load existing users
    db = db_user.loadDB()

    # Check if the user exists
    if username not in db:
        raise ValueError(f"User '{username}' does not exist in the database.") # TO CHANGE

    # Verify the old password
    user = db_user.findUserInDB(username)

    hashed_old_password = crypto.hashPassword(old_password)
    if user.hashedPassword != hashed_old_password:
        raise ValueError("Old password is incorrect.")

    # Hash the new password and update it
    user.hashedPassword = crypto.hashPassword(new_password)
    b64_ct = base64.b64encode(new_encrypted_private_key).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')
    user.encrypted_private_key = b64_ct
    user.nonce = b64_nonce

    updateUserInDB(user)
    print(f"Password for user '{username}' has been updated successfully.")

def updateUserInDB(user : User):
    db_user.createDB()
    db = db_user.loadDB()
    if user.username not in db:
        raise ValueError(f"User '{user.username}' does not exist in the database.")

    # Add the new user to the database
    db[user.username] = asdict(user)

    # Convert bytes to strings for JSON serialization
    db[user.username]["hashedPassword"] = user.hashedPassword.hex() if user.hashedPassword else None
    db[user.username]["public_key"] = user.public_key.decode('utf-8') if user.public_key else None
    db[user.username]["encrypted_private_key"] = user.encrypted_private_key if user.encrypted_private_key else None


    # Save the updated database
    db_user.saveDB(db)
    print(f"Password changed successfully.")
def getNewMessages(username : str, password : str, id_messages : List[int]):
    current_time = datetime.datetime.now()
    messages : List[Message] = db_message.get_new_messages(username,id_messages)

    if len(messages) == 0:
        return None, None

    unlocked_messages = [msg for msg in messages if msg.timeBeforeUnlock <= current_time]
    locked_messages = [msg for msg in messages if msg.timeBeforeUnlock > current_time]

    return unlocked_messages, locked_messages
def getMessageEphemeralPublicKeys(username : str, password : str, id_messages : List[int]) -> dict:
    current_time = datetime.datetime.now()
    ephemeral_keys = db_message.get_ephemeral_public_keys(id_messages)
    if len(ephemeral_keys) == 0:
        return None
    return ephemeral_keys
def sendMessage(_user : User, _message : Message):
    # Additionnal check if the receiver exist???
    # Check if the user is logged in to send message!!
    if db_user.findUserInDB(_message.receiver):
        # Send the message
        next_id = db_message.get_next_message_id()
        _message.id = next_id

        db_message.save_message(_message)

    else:
        print("The receiver '{_message.receiver}' does not exist.")