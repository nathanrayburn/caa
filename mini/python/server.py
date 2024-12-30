import base64
import hashlib
import os
import json
from dataclasses import dataclass, field, asdict
from typing import Optional

# Path to the database file
DB_FILE = "users.json"


@dataclass
class User:
    username: str
    hashedPassword: bytes = field(default=None)
    public_key: bytes = field(default=None)
    encrypted_private_key: bytes = field(default=None)
    nonce: bytes = field(default=None)


def createDB():
    # Path to the JSON file
    db_file = "users.json"

    # Check if the file already exists
    if not os.path.exists(db_file):
        # If it doesn't exist, create an empty JSON file
        with open(db_file, "w") as f:
            json.dump({}, f, indent=4)  # Create an empty JSON object
        print(f"{db_file} created successfully.")
    else:
        print(f"{db_file} already exists.")


def loadDB():
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Database file '{DB_FILE}' does not exist. Please create it first using `createDB`.")
    except json.JSONDecodeError:
        raise ValueError(f"Database file '{DB_FILE}' is corrupted or not a valid JSON file.")
    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred while loading the database: {e}")


# Function to save the database
def saveDB(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)


# Function to hash the password using SHA3
def hashPassword(password: bytes) -> bytes:

    sha3_hasher = hashlib.sha3_512()
    sha3_hasher.update(password)
    return sha3_hasher.digest()


# Function to create a user in the database
def createUserInDB(user: User):
    # Ensure the database exists
    createDB()

    # Load existing users
    db = loadDB()

    # Check if the username already exists
    if user.username in db:
        raise ValueError(f"User '{user.username}' already exists in the database.")

    # Add the new user to the database
    db[user.username] = asdict(user)

    # Convert bytes to strings for JSON serialization
    db[user.username]["hashedPassword"] = user.hashedPassword.hex() if user.hashedPassword else None
    db[user.username]["public_key"] = user.public_key.decode('utf-8') if user.public_key else None
    db[user.username]["encrypted_private_key"] = user.encrypted_private_key if user.encrypted_private_key else None

    # Save the updated database
    saveDB(db)
    print(f"User '{user.username}' created successfully.")


def findUserInDB(username: str) -> Optional[User]:
    try:
        # Load existing users
        createDB()
        db = loadDB()
        # Check if the user exists in the database
        if username in db:
            user_data = db[username]

            # Convert string fields back to bytes
            return User(
                username=user_data["username"],
                hashedPassword=bytes.fromhex(user_data["hashedPassword"]) if user_data["hashedPassword"] else None,
                public_key=user_data["public_key"].encode('utf-8') if user_data["public_key"] else None,
                encrypted_private_key=user_data["encrypted_private_key"].encode('utf-8') if user_data[
                    "encrypted_private_key"] else None,
                nonce=user_data["nonce"].encode('utf-8') if user_data["nonce"] else None
            )
        else:
            return None
    except FileNotFoundError as e:
        print(e)
        return None
    except ValueError as e:
        print(e)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None





# Register
def register(username, password, publicKey, cipheredPrivateKey, nonce):
    # Check if user exists
    userInDB = findUserInDB(username)
    hashedPassword = hashPassword(password)
    b64_ct = base64.b64encode(cipheredPrivateKey).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')
    if userInDB is None:
        createUserInDB(User(
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
    user = findUserInDB(username)
    if not user:
        print("User not found.")
        return False

    # Hash the provided password
    hashedInputPassword = hashPassword(password)

    # Compare the stored hashed password with the hashed input password
    if user.hashedPassword == hashedInputPassword:
        print("Login successful.")
        return user
    else:
        print("Invalid credentials.")
        return False

# Change password
# Function to modify a user's password A VERIFIER
def modifyUserPassword(username: str, old_password: str, new_password: str):
    # Ensure the database exists
    createDB()
    # Load existing users
    db = loadDB()

    # Check if the user exists
    if username not in db:
        raise ValueError(f"User '{username}' does not exist in the database.") # TO CHANGE

    # Verify the old password
    user_data = db[username]
    hashed_old_password = hashPassword(old_password.encode("utf-8"))
    if user_data["hashedPassword"].encode('utf-8') != hashed_old_password:
        raise ValueError("Old password is incorrect.")

    # Hash the new password and update it
    hashed_new_password = hashPassword(new_password.encode("utf-8"))
    user_data["hashedPassword"] = hashed_new_password.decode('utf-8')

    # Save the updated database
    saveDB(db)
    print(f"Password for user '{username}' has been updated successfully.")

# Store messages
