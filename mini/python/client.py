import base64
from typing import List
import datetime

from argon2 import PasswordHasher
from dataclass import user, msg, localmsg
from utils import tools, crypto, signature
from client_database import db_local_message
import server

# Configuration
argon2_hasher = PasswordHasher()

# Data Models
Message = msg.Message
User = user.User
LocalMessage = localmsg

# Helper Functions
def get_input(prompt: str) -> str:
    """Get user input with a given prompt."""
    return input(f"{prompt}: ").strip()

def print_menu(title: str, options: List[str]):
    """Display a menu with a title and numbered options."""
    print(f"\n=== {title} ===")
    for i, option in enumerate(options, start=1):
        print(f"{i}. {option}")
    print("=================")

def get_choice(options: List[str]) -> int:
    """Prompt the user to select a valid menu option."""
    try:
        choice = int(get_input("Choose an option"))
        if 1 <= choice <= len(options):
            return choice
        else:
            raise ValueError
    except ValueError:
        print("Invalid option. Please try again.")
        return None

def get_time_before_unlock() -> datetime.datetime:
    """Prompt the user for a time before unlock and validate the format."""
    while True:
        time_input = get_input("Enter the time before unlock (YYYY-MM-DDTHH:MM:SS)")
        try:
            return datetime.datetime.fromisoformat(time_input)
        except ValueError:
            print("Invalid format. Please use YYYY-MM-DDTHH:MM:SS (e.g., 2024-12-31T12:00:00).")

# Core Functions
def register_client():
    username = get_input("Choose your username")
    password = get_input("Choose your password")

    private_key, public_key = crypto.generate_identity_keypair()
    private_key_bytes = crypto.export_private_key_to_bytes(private_key)
    public_key_bytes = crypto.export_public_key_to_bytes(public_key)

    user_key = crypto.deriveUserKeyFromPassword(username, password)
    hashed_user_key = crypto.hashUserKey(user_key)
    encrypted_private_key, nonce = crypto.encryptPrivateKey(user_key, private_key_bytes)

    server.register(username, hashed_user_key, public_key_bytes, encrypted_private_key, nonce)

def login_client():
    username = get_input("Enter your username")
    password = get_input("Enter your password")

    user_key = crypto.deriveUserKeyFromPassword(username, password)
    hashed_user_key = crypto.hashUserKey(user_key)

    user = server.login(username, hashed_user_key)
    return user, user_key

def send_message_to_user(sender: User):
    receiver = get_input("Enter receiver's username")
    if sender.username == receiver:
        print("You cannot send a message to yourself!")
        return

    content = get_input("Enter your message").encode("utf-8")
    time_before_unlock = get_time_before_unlock()

    receiver_public_key_bytes = server.getUserPublicKey(receiver)
    receiver_public_key = crypto.import_public_key_from_bytes(receiver_public_key_bytes)

    sender_ephemeral_key, nonce, ciphertext = crypto.sender_workflow(receiver_public_key, content)

    sender_private_key_bytes = crypto.decryptPrivateKey(
        sender.userKey, User.getEncryptedPrivateKey(sender), User.getNonce(sender)
    )
    sender_private_key = crypto.import_private_key_from_bytes(sender_private_key_bytes)

    signature_bytes = signature.sign_message(
        sender_private_key, ciphertext + time_before_unlock.isoformat().encode("utf-8")
    )

    message = Message(
        sender=sender.username,
        receiver=receiver,
        content=base64.b64encode(ciphertext).decode("utf-8"),
        nonce=base64.b64encode(nonce).decode("utf-8"),
        senderEphemeralPublicKey=crypto.export_public_key_to_bytes(sender_ephemeral_key),
        timeBeforeUnlock=time_before_unlock,
        signature=base64.b64encode(signature_bytes).decode("utf-8"),
    )

    server.sendMessage(sender, message)
    print("Message sent successfully!")

def modify_password(user: User):
    old_password = get_input("Enter your old password")
    user_key = crypto.deriveUserKeyFromPassword(user.username, old_password)
    hashed_password = crypto.hashUserKey(user_key)

    private_key = crypto.decryptPrivateKey(user_key, User.getEncryptedPrivateKey(user), User.getNonce(user))

    new_password = get_input("Enter your new password")
    new_user_key = crypto.deriveUserKeyFromPassword(user.username, new_password)
    new_hashed_user_key = crypto.hashUserKey(new_user_key)
    encrypted_private_key, nonce = crypto.encryptPrivateKey(new_user_key, private_key)

    server.modifyPassword(user.username, hashed_password, encrypted_private_key, nonce, new_hashed_user_key)
    print("Password updated successfully!")
def save_unlocked_message(_message: Message, decrypted_message):
    # Save or update decrypted message locally
    if not db_local_message.message_exists_locally(_message.id):
        db_local_message.save_message(
            message_id=_message.id,
            sender=_message.sender,
            receiver=_message.receiver,
            content=_message.content,
            nonce=_message.nonce,
            signature=_message.signature,
            senderEphemeralPublicKey=_message.senderEphemeralPublicKey.decode('utf-8'),
            timeBeforeUnlock=_message.timeBeforeUnlock.isoformat(),
            is_decrypted=True,
            decrypted_content=decrypted_message.decode('utf-8')
        )
    else:
        db_local_message.update_message_content(_message.id, decrypted_message.decode('utf-8'))
def get_my_messages(user: User):
    unlocked_messages, locked_messages = server.getUserMessages(user.username, user.hashedPassword)
    download_messages(user, unlocked_messages, locked_messages)

def download_new_messages(user: User):
    message_ids = db_local_message.getAllMessageIDs()
    unlocked_messages, locked_messages = server.getNewMessages(user.username, user.hashedPassword, message_ids)
    download_messages(user, unlocked_messages, locked_messages)

def unlock_available_messages(user: User):
    message_ids = db_local_message.getUndecryptedUnlockedMessageIDs()
    ephemeral_keys = server.getMessageEphemeralPublicKeys(user.username, user.hashedPassword, message_ids)
    if not ephemeral_keys:
        print("No messages are ready to be unlocked.")
        return

    for message_id, ephemeral_key in ephemeral_keys.items():
        if ephemeral_key:
            local_message = db_local_message.get_message_by_id(message_id)
            local_message.senderEphemeralPublicKey = ephemeral_key
            message = tools.convert_local_to_message(local_message)
            receive_message_from_user(user, message)
def save_locked_message(message: Message):
    """Save locked messages locally if they don't already exist."""
    if not db_local_message.message_exists_locally(message.id):
        db_local_message.save_message(
            message_id=message.id,
            sender=message.sender,
            receiver=message.receiver,
            content=message.content,
            nonce=message.nonce,
            signature=message.signature,
            timeBeforeUnlock=message.timeBeforeUnlock.isoformat(),
        )
def download_messages(user: User, unlocked_messages: List[Message], locked_messages: List[Message]):
    if not unlocked_messages and not locked_messages:
        print("No messages found.")
        return

    print(f"Unlocked messages: {len(unlocked_messages)}")
    print(f"Locked messages: {len(locked_messages)}")

    for _message in unlocked_messages:
        decrypted_message = receive_message_from_user(user, _message)
        if decrypted_message:
            print(f"From {_message.sender}: {decrypted_message}")
    for _message in locked_messages:
        save_locked_message(_message)

def receive_message_from_user(user: User, _message: Message):
    private_key_bytes = crypto.decryptPrivateKey(user.userKey, User.getEncryptedPrivateKey(user), User.getNonce(user))
    private_key = crypto.import_private_key_from_bytes(private_key_bytes)

    sender_public_key_bytes = server.getUserPublicKey(_message.sender)
    sender_public_key = crypto.import_public_key_from_bytes(sender_public_key_bytes)


    nonce =   base64.b64decode(_message.nonce.encode("utf-8"))
    content = base64.b64decode(_message.content.encode("utf-8"))
    signature_valid = signature.verify_signature(
        sender_public_key,
        content + _message.timeBeforeUnlock.isoformat().encode("utf-8"),
        base64.b64decode(_message.signature),
    )
    if signature_valid:
        decrypted_message = crypto.receiver_workflow(private_key, crypto.import_public_key_from_bytes(_message.senderEphemeralPublicKey), nonce, content)
        print(f"Message has a valid signature: {decrypted_message}")
        save_unlocked_message(_message, decrypted_message)
        print("Valid message received.")
        return decrypted_message.decode("utf-8")
    else:
        print("Invalid signature.")
        return None

# Menus
def main_menu():
    options = ["Register", "Login", "Quit"]
    while True:
        print_menu("Main Menu", options)
        choice = get_choice(options)
        if choice == 1:
            register_client()
        elif choice == 2:
            user, user_key = login_client()
            if user:
                user.userKey = user_key
                logged_menu(user)
            else:
                print("Login failed. Please try again.")
        elif choice == 3:
            print("Goodbye!")
            break

def logged_menu(user: User):
    options = [
        "Send Message",
        "Get My Messages",
        "Download New Messages",
        "Unlock Available Messages",
        "Modify Password",
        "Logout",
    ]
    while True:
        print_menu("Logged Menu", options)
        choice = get_choice(options)
        if choice == 1:
            send_message_to_user(user)
        elif choice == 2:
            get_my_messages(user)
        elif choice == 3:
            download_new_messages(user)
        elif choice == 4:
            unlock_available_messages(user)
        elif choice == 5:
            modify_password(user)
            break
        elif choice == 6:
            print("Logging out...")
            break

# Main Entry Point
if __name__ == "__main__":
    main_menu()
