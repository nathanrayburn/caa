import base64
from typing import List

import server

import datetime

from argon2 import PasswordHasher

# Configuration
# Initialize the Argon2 password hasher
argon2_hasher = PasswordHasher()

from dataclass import user
from dataclass import msg
from dataclass import localmsg
from utils import tools
from utils import crypto
from utils import signature
from client_database import db_local_message
Message = msg.Message
User = user.User
LocalMessage = localmsg

def registerClient():
    # get username input
    username = input("Choose your username: ")
    # get password input
    password = input("Choose your password: ")
    # generate keys
    private_key, public_key = crypto.generate_identity_keypair()
    private_key_bytes = crypto.export_private_key_to_bytes(private_key)

    public_key_bytes = crypto.export_public_key_to_bytes(public_key)
    userkey = crypto.deriveUserKeyFromPassword(username, password)

    hasheduserkey = crypto.hashUserKey(userkey)

    # Encrypt private key
    encryptedprivatekey, nonce = crypto.encryptPrivateKey(userkey, private_key_bytes)

    # register to server
    server.register(username, hasheduserkey, public_key_bytes, encryptedprivatekey, nonce)

def loginClient():

    username = input("Enter your username: ")

    password = input("Enter your password: ")

    userkey = crypto.deriveUserKeyFromPassword(username, password)

    hasheduserkey = crypto.hashUserKey(userkey)

    return server.login(username, hasheduserkey), userkey


def get_time_before_unlock():
    while True:
        time_input = input("Enter the time before unlock (YYYY-MM-DDTHH:MM:SS): ")
        try:
            # Parse the input using ISO 8601 format
            time_obj = datetime.datetime.fromisoformat(time_input)
            return time_obj
        except ValueError:
            print("Invalid format. Please use YYYY-MM-DDTHH:MM:SS (e.g., 2024-12-31T12:00:00).")




def main():
    main_menu()

def main_menu():
    while True:
        print("\n=== Main Menu ===")
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        print("=================\n")
        choice = input("Choose an option: ")

        if choice == "1":
            registerClient()
        elif choice == "2":
            user, userkey = loginClient()
            if user:
                user.userKey = userkey
                logged_menu(user)
            else:
                print("TA MERE LA PUTE")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
def sendMessageToUser(sender : User, receiverUsername, plaintext, timeBeforeUnlock : datetime):

    # Get receiver public key
    if sender.username == receiverUsername:
        print("Cannot send message to yourself!")
        return
    receiver_public_key_bytes = server.getUserPublicKey(receiverUsername)

    receiver_public_key = crypto.import_public_key_from_bytes(receiver_public_key_bytes)

    sender_ephemeral_key, nonce, ciphertext = crypto.sender_workflow(receiver_public_key, plaintext)

    sender_private_key_bytes = crypto.decryptPrivateKey(sender.userKey, User.getEncryptedPrivateKey(sender),
                                                   User.getNonce(sender))
    sender_private_key = crypto.import_private_key_from_bytes(sender_private_key_bytes)

    s = signature.sign_message(sender_private_key, ciphertext + timeBeforeUnlock.isoformat().encode('utf-8'))

    print(ciphertext)
    b64_signature = base64.b64encode(s).decode('utf-8')
    b64_nonce     = base64.b64encode(nonce).decode('utf-8')
    b64_cipher    = base64.b64encode(ciphertext).decode('utf-8')
    # Create message with given date
    _message = Message(sender=sender.username, content=b64_cipher, receiver=receiverUsername, senderEphemeralPublicKey=crypto.export_public_key_to_bytes(sender_ephemeral_key), nonce=b64_nonce, timeBeforeUnlock=timeBeforeUnlock, signature=b64_signature)
    # Store into server
    server.sendMessage(sender, _message)
    print("Message sent to server.")
def saveLockedMessages(_message: Message):
    if not db_local_message.message_exists_locally(_message.id):
        db_local_message.save_message(
            message_id=_message.id,
            sender=_message.sender,
            receiver=_message.receiver,
            content=_message.content,
            nonce=_message.nonce,
            signature=_message.signature,
            timeBeforeUnlock=_message.timeBeforeUnlock.isoformat()
        )
def saveUnlockedMessages(_message: Message, decrypted_message):
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

def downloadMessages(user: User,unlocked_messages : List[Message], locked_messages : List[Message]):
    if not unlocked_messages and not locked_messages:
        print("No messages found.")
        return

    print("---------------------------------------")
    print(f"Available {len(unlocked_messages)} messages")
    print(f"Locked {len(locked_messages)} messages")

    # Process unlocked messages
    for _message in unlocked_messages:
        decryptedmessage = receiveMessageFromUser(user, _message)
        if decryptedmessage is not None:
            print(f"From user {_message.sender}: {decryptedmessage}")

    # Save locked messages locally
    for _message in locked_messages:
        saveLockedMessages(_message)
    print("---------------------------------------")

def getMyMessages(user: User):
    unlocked_messages, locked_messages = server.getUserMessages(user.username, user.hashedPassword)
    downloadMessages(user, unlocked_messages, locked_messages)

def receiveMessageFromUser(receiver: User, _message):
    receiver_private_key_bytes = crypto.decryptPrivateKey(receiver.userKey, User.getEncryptedPrivateKey(receiver),
                                                   User.getNonce(receiver))
    receiver_private_key = crypto.import_private_key_from_bytes(receiver_private_key_bytes)

    s = Message.getSignature(_message)
    nonce = Message.getNonce(_message)
    ciphertext = Message.getContent(_message)

    sender_ephemeral_key = crypto.import_public_key_from_bytes(_message.senderEphemeralPublicKey)

    sender_public_key_bytes = server.getUserPublicKey(_message.sender)

    sender_public_key = crypto.import_public_key_from_bytes(sender_public_key_bytes)

    s_valid = signature.verify_signature(sender_public_key, ciphertext + _message.timeBeforeUnlock.isoformat().encode('utf-8'), s)
    if s_valid:
        decrypted_message = crypto.receiver_workflow(receiver_private_key, sender_ephemeral_key, nonce, ciphertext)
        print(f"Message has a valid signature: {decrypted_message}")
        saveUnlockedMessages(_message, decrypted_message)

        return decrypted_message
    else:
        print("Couldn't validate the message's signature.")
        return None
def downloadNewMessages(user : User):
    id_messages: List[int] = db_local_message.getAllMessageIDs()
    unlocked_messages, locked_messages = server.getNewMessages(user.username, user.hashedPassword, id_messages)
    downloadMessages(user, unlocked_messages, locked_messages)
def unlockMessages(user : User, ephemeral_keys : dict):
    # Iterate through the dictionary
    for key, value in ephemeral_keys.items():
        if value:
            _localMessage : LocalMessage = db_local_message.get_message_by_id(key)
            _localMessage.senderEphemeralPublicKey = value
            _message = tools.convert_local_to_message(_localMessage)
            receiveMessageFromUser(user, _message)

def unlockAvailableMessages(user : User):
    id_messages : List[int] = db_local_message.getUndecryptedUnlockedMessageIDs()
    ephemeral_keys = server.getMessageEphemeralPublicKeys(user.username, user.hashedPassword, id_messages)
    unlockMessages(user, ephemeral_keys)
    return None
def logged_menu(user):
    while True:
        print("\n=== Logged Menu ===")
        print("1. Send message")
        print("2. Get my messages")
        print("3. Download new messages")
        print("4. Unlock available messages")
        print("5. Modify password")
        print("6. Logout")
        choice = input("Choose an option: ")
        if choice == "1":
            content = input("Enter your message: ")
            receiver = input("Enter your receiver: ")
            timebeforeunlock = get_time_before_unlock()
            content_bytes = content.encode('utf-8')
            sendMessageToUser(user, receiver, content_bytes, timebeforeunlock)
        elif choice == "2":
            getMyMessages(user)
        elif choice == "3":
            downloadNewMessages(user)
        elif choice == "4":
            unlockAvailableMessages(user)
        elif choice == "5":
            password = input("Enter your old password: ")
            userkey = crypto.deriveUserKeyFromPassword(user.username, password)
            hashedPassword = crypto.hashUserKey(userkey)
            private_key = crypto.decryptPrivateKey(userkey, User.getEncryptedPrivateKey(user), User.getNonce(user))

            new_password = input("Enter your new password: ")
            newUserkey = crypto.deriveUserKeyFromPassword(user.username, new_password)
            newHashedUserkey = crypto.hashUserKey(newUserkey)

            new_encrypted_private_key, nonce = crypto.encryptPrivateKey(newUserkey, private_key)

            user = server.modifyPassword(user.username, hashedPassword, new_encrypted_private_key, nonce, newHashedUserkey)
            break;
        elif choice == "6":
            print("Goodbye!")
            break
main()