import os
import json
from dataclasses import asdict
from typing import Optional
from dataclass import user


User = user.User


# Path to the database file
DB_FILE = "users.json"
# Function to save the database
def saveDB(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)
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

