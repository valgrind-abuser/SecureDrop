import json
import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

USERS_FILE = "users.json"
RSA_PRIVATE_KEY_FILE = "rsa_private_key.pem"
RSA_PUBLIC_KEY_FILE = "rsa_public_key.pem"

PBKDF2_ITERATIONS = 100000

# ---------- RSA + AES for encrypting users.json ----------

def generate_rsa_keys():
    # One RSA key pair per client, used to wrap AES keys for users.json
    if os.path.exists(RSA_PRIVATE_KEY_FILE) and os.path.exists(RSA_PUBLIC_KEY_FILE):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(RSA_PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    public_key = private_key.public_key()
    with open(RSA_PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def load_rsa_keys():
    generate_rsa_keys()
    with open(RSA_PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(RSA_PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


def encrypt_data(plaintext_bytes):
    # Hybrid crypto: random AES key, then encrypt that AES key with RSA
    private_key, public_key = load_rsa_keys()

    aes_key = os.urandom(32)      # 256-bit AES key
    nonce = os.urandom(12)        # 96-bit nonce for AES-GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    data = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    return data


def decrypt_data(data):
    private_key, public_key = load_rsa_keys()

    encrypted_key = base64.b64decode(data["encrypted_key"])
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


# ---------- password hashing (PBKDF2) ----------

def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(dk).decode("utf-8")
    return salt_b64, hash_b64


def verify_password(password, salt_b64, hash_b64):
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    real_hash = base64.b64decode(hash_b64.encode("utf-8"))
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(real_hash, test_hash)


# ---------- per-user key pairs (for later auth/file transfer) ----------

def generate_user_keys():
    # One RSA key pair per user, used later for auth/file-transfer protocols
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_b64 = base64.b64encode(public_pem).decode("utf-8")
    private_b64 = base64.b64encode(private_pem).decode("utf-8")
    return public_b64, private_b64


# ---------- CLI + user logic ----------

def print_commands():
    print("add\nhelp\nsend\nlist\nexit\n")
    return


def file_send(current_user, args):
    if len(args) < 2:
        print("Command format is send <email address> <filename> ")
        return
    target_email, file_name = args
    print(f"Sending {file_name} to {target_email}...")
    # TODO: plug in real secure file transfer (RSA + AES) in Milestone 5
    return 0


def online_list():
    # TODO: replace with real online list using network later (Milestone 4)
    return []


def exit_secure_drop():
    exit(1)


def load_users():
    # Load all users from json file (if file exists)
    if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
        return {}

    with open(USERS_FILE, "r") as file:
        data = json.load(file)

    # encrypted format (our new format)
    if isinstance(data, dict) and "encrypted_key" in data:
        plaintext = decrypt_data(data)
        try:
            users = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return users

    # plain JSON (older version, list or dict)
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        users = {}
        for user in data:
            email = user.get("email address") or user.get("email")
            if email:
                users[email] = user
        return users

    return {}


def save_users(users):
    plaintext = json.dumps(users, indent=4).encode("utf-8")
    enc_data = encrypt_data(plaintext)
    with open(USERS_FILE, "w") as file:
        json.dump(enc_data, file, indent=4)


def email_exists(users, email):
    return email in users


users = load_users()       # global scope


def register_user():
    global users
    while True:
        RegnameInput = input("Enter Full Name: ")
        Regemail = input("Enter email address: ")

        if Regemail in users:
            print("User already registered. ")
            return

        Regpassword = input("Enter password: ")
        Regpassword2 = input("Re-enter password: ")
        if Regpassword == Regpassword2:
            print("Passwords Match. ")
            break
        else:
            print("Passwords Did Not Match. Please Try Again. ")

    # hash the password instead of storing plaintext
    salt_b64, hash_b64 = hash_password(Regpassword)

    # generate per-user RSA key pair (for later auth/file transfer)
    public_b64, private_b64 = generate_user_keys()

    users[Regemail] = {
        "name": RegnameInput,
        "password_salt": salt_b64,
        "password_hash": hash_b64,
        "contacts": [],
        "Pending Request": [],
        "public_key": public_b64,
        "private_key": private_b64
    }
    save_users(users)


# helper func for contact requests
def send_request(sender_email, args):
    if len(args) < 1:
        print('Command format is "add" <email address>')
        return
    target_email = args[0]
    if target_email not in users:
        print("User not found. ")
        return
    target = users[target_email]
    if sender_email in target["Pending Request"]:
        print("Already sent request to this user. ")
        return
    target["Pending Request"].append(sender_email)
    save_users(users)
    print(f"Friend request sent to {target_email}")


commands = {
    "add": send_request,
    "help": print_commands,
    "send": file_send,
    "list": online_list,
    "exit": exit_secure_drop
}


def user_login():
    global users
    # reload users from disk in case file changed
    users = load_users()
    while True:
        email_login = input("Enter email address: ")
        password_login = input("Enter your password: ")

        if email_login in users:
            user = users[email_login]
            salt = user.get("password_salt")
            pwd_hash = user.get("password_hash")
            if salt and pwd_hash and verify_password(password_login, salt, pwd_hash):
                print("Login Successful")
                user_menu(email_login)
                return
        print("Email and password combination not valid")


def user_menu(current_user):
    print(f"Welcome to SecureDrop!\nType 'help' for commands")
    while True:
        user_input = input("> ").strip()
        if not user_input:
            continue
        parts = user_input.split()
        cmd, *args = parts
        if cmd in commands:
            if cmd == "help":
                commands[cmd]()
                continue
            elif cmd == "exit":
                commands[cmd]()
                continue
            commands[cmd](current_user, args)
        else:
            # invalid command should not crash or exit
            print("Not valid command. ")


if __name__ == "__main__":
    # Simple entry behavior:
    # - Ask if user wants to register.
    #   * if yes: register then exit (Milestone 1 style).
    #   * if no: go to login loop.
    Register_choice = input('Do you want to register a new user (y/n)? ')
    if Register_choice == 'Y' or Register_choice == 'y':
        register_user()
        print('User Registered.')
        print('Exiting SecureDrop...')
        exit()
    else:
        user_login()
        print("End of program so far...")
        exit(1)