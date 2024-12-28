from nacl import pwhash, secret, utils


# Configuration
kdf = pwhash.argon2i.kdf
ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
mem = pwhash.argon2i.MEMLIMIT_SENSITIVE

# exemple Alices_key = kdf(secret.SecretBox.KEY_SIZE, password, salt, opslimit=ops, memlimit=mem)
# Get User password
def register_password():
    # check max size length
    return "password"
def register_username():
    return "username"
def register_account():
    # get username
    # get password
    # generate public and private keys
def encrypt_private_key(private_key, user_key):
    return ""
def hkdf_username(username):
    salt = b""
    return kdf(secret.SecretBox.KEY_SIZE, username, salt, opslimit=ops, memlimit=mem)
# KDF That returns key to cipher the private key. Inputs password and HKDF ( username )
def hkdf_password(password, username):
    salt = username
    return kdf(secret.SecretBox.KEY_SIZE, password, salt, opslimit=ops, memlimit=mem)
# This function is the hash that is sent to the server ( used as password for login )
def hkdf_password_server_hash(user_key):
    salt = b""
    return kdf(secret.SecretBox.KEY_SIZE, user_key, salt, opslimit=ops, memlimit=mem)
# HKDF That returns the hashed password.
