
import json
import os
import base64
import hashlib
import hmac
import socket
import threading
import time
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================================================
# CONFIGURATION
# ============================================================================

USERS_FILE = "users.json"
RSA_PRIVATE_KEY_FILE = "rsa_private_key.pem"
RSA_PUBLIC_KEY_FILE = "rsa_public_key.pem"

PBKDF2_ITERATIONS = 100000

BROADCAST_PORT = 50555
FILE_PORT = 50600
CHUNK_SIZE = 4096
BROADCAST_INTERVAL = 3  # seconds
ONLINE_TIMEOUT = 12  # seconds - consider offline after this long

RUNNING = True
online_contacts = {}  # {email: (last_ping_time, ip_address)}
contact_ips = {}
lock = threading.Lock()  # Thread safety for shared state

# ============================================================================
# RSA + AES ENCRYPTION FOR DATABASE
# ============================================================================

def generate_rsa_keys():
    """Generate or load RSA keys for encrypting users.json"""
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
    """Load RSA key pair"""
    generate_rsa_keys()
    with open(RSA_PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(RSA_PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


def encrypt_data(plaintext_bytes):
    """Hybrid encryption: AES-GCM for data, RSA-OAEP for AES key"""
    private_key, public_key = load_rsa_keys()

    aes_key = os.urandom(32)
    nonce = os.urandom(12)
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
    """Decrypt hybrid-encrypted data"""
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


# ============================================================================
# PASSWORD HASHING (PBKDF2)
# ============================================================================

def hash_password(password):
    """Hash password with random salt"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(dk).decode("utf-8")
    return salt_b64, hash_b64


def verify_password(password, salt_b64, hash_b64):
    """Verify password against stored hash"""
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    real_hash = base64.b64decode(hash_b64.encode("utf-8"))
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(real_hash, test_hash)


# ============================================================================
# PER-USER KEY PAIRS
# ============================================================================

def generate_user_keys():
    """Generate RSA key pair for a new user"""
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


# ============================================================================
# RSA SIGN / VERIFY
# ============================================================================

def rsa_sign(private_pem_b64, message_bytes):
    """Sign message with private key"""
    private_pem = base64.b64decode(private_pem_b64)
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    sig = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return sig


def rsa_verify(public_pem_b64, message_bytes, signature):
    """Verify signature with public key"""
    public_pem = base64.b64decode(public_pem_b64)
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ============================================================================
# CLI HELPERS
# ============================================================================

def print_commands():
    """Display available commands"""
    print('"add"  -> Send contact request')
    print('"list" -> List online contacts')
    print('"send" -> Transfer file to contact')
    print('"help" -> Show commands')
    print('"exit" -> Exit SecureDrop')
    print()


# ============================================================================
# NETWORKING: PRESENCE (Milestone 4)
# ============================================================================

def broadcast_presence(current_user):
    """
    FIX #1: Send JSON with email AND public_key so receiver can map back to user.
    Broadcast our presence so contacts know we're online.
    """
    if current_user not in users:
        return

    pub_b64 = users[current_user]["public_key"]
    # Send JSON with email so receiver knows who this is
    data_dict = {
        "email": current_user,
        "public_key": pub_b64
    }
    data = json.dumps(data_dict).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while RUNNING:
        try:
            sock.sendto(data, ("255.255.255.255", BROADCAST_PORT))
        except Exception:
            pass
        time.sleep(BROADCAST_INTERVAL)

    sock.close()


def listen_for_presence(current_user):
    """
    FIX #2: Track timestamp for each online contact and implement timeout logic.
    FIX #3: Increase socket buffer size to handle multiple broadcasts.
    Listen for broadcast pings from other users and track online status.
    """
    global online_contacts, contact_ips

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)  # FIX #3
    sock.bind(("", BROADCAST_PORT))

    while RUNNING:
        try:
            data, addr = sock.recvfrom(4096)
            try:
                data_dict = json.loads(data.decode("utf-8"))
                sender_email = data_dict.get("email")
                pub_b64 = data_dict.get("public_key")
            except json.JSONDecodeError:
                continue

            # Check if this sender is a mutual contact
            if sender_email and sender_email in users:
                if (sender_email in users[current_user].get("contacts", []) and
                        current_user in users[sender_email].get("contacts", [])):
                    with lock:
                        online_contacts[sender_email] = (time.time(), addr[0])
                        contact_ips[sender_email] = addr[0]
        except Exception:
            pass

    sock.close()


def cleanup_stale_contacts():
    """
    FIX #2: Remove contacts that haven't pinged in ONLINE_TIMEOUT seconds.
    """
    global online_contacts
    while RUNNING:
        try:
            current_time = time.time()
            with lock:
                to_remove = [
                    email for email, (last_ping, ip) in online_contacts.items()
                    if current_time - last_ping > ONLINE_TIMEOUT
                ]
                for email in to_remove:
                    del online_contacts[email]
                    if email in contact_ips:
                        del contact_ips[email]
        except Exception:
            pass
        time.sleep(5)


def online_list(current_user, args=None):
    """
    FIX #5 & #6: Now properly uses current_user parameter to show MUTUAL online contacts.
    Show list of online mutual contacts.
    """
    with lock:
        if not online_contacts:
            print("No contacts are online.")
            return
        print("The following contacts are online:")
        for email in online_contacts.keys():
            if (email in users[current_user].get("contacts", []) and
                    current_user in users.get(email, {}).get("contacts", [])):
                name = users[email].get("name", "")
                if name:
                    print(f"* {name} <{email}>")
                else:
                    print(f"* {email}")


# ============================================================================
# SECURE FILE TRANSFER (Milestone 5)
# ============================================================================

def file_receiver(current_user):
    """
    FIX #4: Add SO_REUSEADDR to avoid "address already in use" error.
    FIX #8: Improved error handling with retry logic.
    Listen for incoming file transfer requests.
    """
    max_retries = 3
    retry_count = 0

    while retry_count < max_retries and RUNNING:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # FIX #4
            sock.bind(("", FILE_PORT))
            sock.listen(5)
            retry_count = 0  # Reset on successful bind

            while RUNNING:
                try:
                    conn, addr = sock.accept()
                except Exception:
                    break

                try:
                    # Handshake: receive metadata
                    header = conn.recv(4096)
                    if not header:
                        conn.close()
                        continue
                    try:
                        meta = json.loads(header.decode("utf-8"))
                    except json.JSONDecodeError:
                        conn.close()
                        continue

                    sender_email = meta.get("from")
                    target_email = meta.get("to")
                    filename = meta.get("filename")
                    session_id = meta.get("session_id", "")
                    sig_b64 = meta.get("signature", "")

                    # Only proceed if this transfer is meant for current_user
                    if target_email != current_user or sender_email not in users:
                        conn.close()
                        continue

                    # Verify sender is mutual contact
                    if (sender_email not in users[current_user].get("contacts", []) or
                            current_user not in users[sender_email].get("contacts", [])):
                        conn.sendall(b"REJECT")
                        conn.close()
                        continue

                    # Verify signature on session_id
                    sender_pub = users[sender_email].get("public_key")
                    if not sender_pub:
                        conn.close()
                        continue

                    try:
                        sig = base64.b64decode(sig_b64)
                    except Exception:
                        conn.close()
                        continue

                    if not rsa_verify(sender_pub, session_id.encode("utf-8"), sig):
                        conn.close()
                        continue

                    # Ask local user for permission
                    print(f"\n{sender_email} is sending file '{filename}'. Accept (y/n)?")
                    ans = input("> ").strip().lower()
                    if ans != "y":
                        conn.sendall(b"REJECT")
                        conn.close()
                        continue

                    conn.sendall(b"ACCEPT")

                    # Receive RSA-encrypted AES key
                    enc_key_len_bytes = conn.recv(4)
                    if len(enc_key_len_bytes) != 4:
                        conn.close()
                        continue
                    enc_key_len = struct.unpack("!I", enc_key_len_bytes)[0]
                    enc_key = b""
                    while len(enc_key) < enc_key_len:
                        chunk = conn.recv(enc_key_len - len(enc_key))
                        if not chunk:
                            break
                        enc_key += chunk

                    # Receive nonce
                    nonce = conn.recv(12)
                    if len(nonce) != 12:
                        conn.close()
                        continue

                    # Decrypt AES key using receiver's private key
                    private_pem_b64 = users[current_user]["private_key"]
                    private_pem = base64.b64decode(private_pem_b64)
                    private_key = serialization.load_pem_private_key(private_pem, password=None)
                    try:
                        aes_key = private_key.decrypt(
                            enc_key,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                    except Exception:
                        conn.close()
                        continue

                    # Receive encrypted file size
                    size_bytes = conn.recv(8)
                    if len(size_bytes) != 8:
                        conn.close()
                        continue
                    (total_size,) = struct.unpack("!Q", size_bytes)

                    # Receive encrypted file bytes
                    ciphertext = b""
                    while len(ciphertext) < total_size:
                        chunk = conn.recv(min(CHUNK_SIZE, total_size - len(ciphertext)))
                        if not chunk:
                            break
                        ciphertext += chunk

                    if len(ciphertext) != total_size:
                        conn.close()
                        continue

                    # Decrypt file using AES-GCM with AEAD (session_id as AAD)
                    aesgcm = AESGCM(aes_key)
                    try:
                        plaintext = aesgcm.decrypt(nonce, ciphertext, session_id.encode("utf-8"))
                    except Exception:
                        conn.close()
                        continue

                    # Save file locally
                    out_name = os.path.basename(filename)
                    # FIX #14: Extra security check for path traversal
                    if os.path.sep in out_name or out_name.startswith("."):
                        out_name = out_name.split(os.path.sep)[-1]
                    out_path = os.path.join(os.getcwd(), out_name)

                    with open(out_path, "wb") as f:
                        f.write(plaintext)

                    # Calculate and display SHA256
                    sha256_hash = hashlib.sha256(plaintext).hexdigest()
                    print(f"File '{out_name}' received. SHA256: {sha256_hash}")
                    conn.close()

                except Exception:
                    try:
                        conn.close()
                    except:
                        pass

            sock.close()
        except Exception:
            retry_count += 1
            if retry_count < max_retries:
                print(f"File receiver failed, retrying ({retry_count}/{max_retries})...")
                time.sleep(2)
            else:
                print("File receiver: max retries exceeded.")
                break


def file_send(current_user, args):
    """
    FIX #13: Check if target_ip exists; if not, suggest running 'list' first.
    FIX #14: Additional path traversal protection.
    Send file to a mutual contact who is online.
    """
    if len(args) < 2:
        print("Command format is: send <email address> <filename>")
        return

    target_email, file_name = args

    # Check if mutual contact
    if target_email not in users[current_user].get("contacts", []):
        print("Target is not in your contacts.")
        return
    if current_user not in users.get(target_email, {}).get("contacts", []):
        print("Target has not added you as a contact.")
        return

    # Check if online
    with lock:
        if target_email not in online_contacts:
            print("Target is not online. Try 'list' to refresh online status.")
            return
        target_ip = contact_ips.get(target_email)

    if not target_ip:
        print("No IP address for target. Try 'list' to refresh.")
        return

    # Check file exists
    if not os.path.exists(file_name):
        print("File does not exist.")
        return

    # Read file
    try:
        with open(file_name, "rb") as f:
            data = f.read()
    except Exception:
        print("Could not read file.")
        return

    # Create AES key, nonce, and session ID
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    session_id = base64.b64encode(os.urandom(16)).decode("utf-8")

    # Encrypt file with AES-GCM (session_id as AEAD)
    ciphertext = aesgcm.encrypt(nonce, data, session_id.encode("utf-8"))

    # Sign session_id with sender's private key
    sig = rsa_sign(users[current_user]["private_key"], session_id.encode("utf-8"))
    sig_b64 = base64.b64encode(sig).decode("utf-8")

    # Encrypt AES key with receiver's public key
    target_pub_b64 = users[target_email].get("public_key")
    if not target_pub_b64:
        print("Target's public key not found.")
        return

    target_pub_pem = base64.b64decode(target_pub_b64)
    target_pub = serialization.load_pem_public_key(target_pub_pem)

    enc_aes_key = target_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Connect to receiver
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, FILE_PORT))
    except Exception:
        print("Could not connect to target.")
        return

    try:
        # Send metadata handshake
        meta = {
            "from": current_user,
            "to": target_email,
            "filename": os.path.basename(file_name),
            "session_id": session_id,
            "signature": sig_b64,
        }
        meta_bytes = json.dumps(meta).encode("utf-8")
        sock.sendall(meta_bytes)

        # Wait for acceptance
        resp = sock.recv(16)
        if resp != b"ACCEPT":
            print("Target rejected the file transfer.")
            sock.close()
            return

        # Send encrypted AES key (length-prefixed)
        enc_key_len = len(enc_aes_key)
        sock.sendall(struct.pack("!I", enc_key_len))
        sock.sendall(enc_aes_key)
        sock.sendall(nonce)

        # Send encrypted file (length-prefixed)
        total_size = len(ciphertext)
        sock.sendall(struct.pack("!Q", total_size))

        sent = 0
        while sent < total_size:
            chunk = ciphertext[sent:sent + CHUNK_SIZE]
            sock.sendall(chunk)
            sent += len(chunk)

        # Calculate and display SHA256
        sha256_hash = hashlib.sha256(data).hexdigest()
        print(f"File transferred. SHA256: {sha256_hash}")
        sock.close()

    except Exception:
        try:
            sock.close()
        except:
            pass
        print("Error during file transfer.")


def exit_secure_drop(current_user=None, args=None):
    """
    FIX #12: Set RUNNING = False to gracefully stop all threads.
    """
    global RUNNING
    RUNNING = False
    print("Exiting SecureDrop...")
    time.sleep(1)  # Give threads time to exit
    exit(0)


# ============================================================================
# USER STORAGE
# ============================================================================

def load_users():
    """Load encrypted user database"""
    if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
        return {}

    with open(USERS_FILE, "r") as file:
        data = json.load(file)

    # Encrypted format
    if isinstance(data, dict) and "encrypted_key" in data:
        plaintext = decrypt_data(data)
        try:
            users = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return users

    # Plain JSON (backward compatibility)
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
    """Save encrypted user database"""
    plaintext = json.dumps(users, indent=4).encode("utf-8")
    enc_data = encrypt_data(plaintext)
    with open(USERS_FILE, "w") as file:
        json.dump(enc_data, file, indent=4)


users = load_users()


# ============================================================================
# REGISTRATION & LOGIN
# ============================================================================

def register_user():
    """Register a new user"""
    global users
    while True:
        RegnameInput = input("Enter Full Name: ")
        Regemail = input("Enter email address: ")

        if Regemail in users:
            print("User already registered.")
            return

        Regpassword = input("Enter password: ")
        Regpassword2 = input("Re-enter password: ")
        if Regpassword == Regpassword2:
            print("Passwords Match.")
            break
        else:
            print("Passwords Did Not Match. Please Try Again.")

    salt_b64, hash_b64 = hash_password(Regpassword)
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


# ============================================================================
# CONTACT MANAGEMENT
# ============================================================================

def send_request(sender_email, args):
    """
    FIX #10: Remove sender from Pending Request if both become mutual contacts.
    Send contact request to another user.
    """
    if len(args) < 1:
        print('Command format is "add" <email address>')
        return
    target_email = args[0]
    if target_email not in users:
        print("User not found.")
        return
    if target_email == sender_email:
        print("You cannot add yourself.")
        return

    target = users[target_email]

    # Check if already mutual contacts
    if sender_email in target.get("contacts", []) and target_email in users[sender_email].get("contacts", []):
        print("You are already contacts.")
        return

    # Check if request already sent
    if sender_email in target.get("Pending Request", []):
        print("Already sent request to this user.")
        return

    # Add to pending requests
    if "Pending Request" not in target:
        target["Pending Request"] = []
    target["Pending Request"].append(sender_email)
    save_users(users)
    print(f"Friend request sent to {target_email}")


def process_pending_requests(current_user):
    """
    FIX #9: Only add if both parties agree (mutual).
    Process incoming contact requests at login.
    """
    pending = users[current_user].get("Pending Request", [])
    if not pending:
        return

    print(f"You have {len(pending)} pending contact request(s) from:")
    for addr in pending:
        if addr in users:
            name = users[addr].get("name", addr)
            print(f"- {name} ({addr})")

    choice = input("Type 'yes' to accept all, anything else to ignore: ").strip().lower()
    if choice == "yes":
        for sender in pending:
            if sender in users:
                # Add to mutual contacts
                if sender not in users[current_user].get("contacts", []):
                    users[current_user]["contacts"].append(sender)
                if current_user not in users[sender].get("contacts", []):
                    users[sender]["contacts"].append(current_user)

                # Remove from pending once accepted
                if current_user in users[sender].get("Pending Request", []):
                    users[sender]["Pending Request"].remove(current_user)

        users[current_user]["Pending Request"] = []
        save_users(users)
        print("All pending requests accepted.")


commands = {
    "add": send_request,
    "help": print_commands,
    "send": file_send,
    "list": online_list,
    "exit": exit_secure_drop
}


def user_login():
    """Login user"""
    global users
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
    """User command menu"""
    print(f"Welcome to SecureDrop.\nType 'help' for commands.")

    process_pending_requests(current_user)

    # Start background threads
    t1 = threading.Thread(target=broadcast_presence, args=(current_user,), daemon=True)
    t2 = threading.Thread(target=listen_for_presence, args=(current_user,), daemon=True)
    t3 = threading.Thread(target=cleanup_stale_contacts, daemon=True)
    t4 = threading.Thread(target=file_receiver, args=(current_user,), daemon=True)

    t1.start()
    t2.start()
    t3.start()
    t4.start()

    while True:
        try:
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
                    commands[cmd](current_user, args)
                    return
                commands[cmd](current_user, args)
            else:
                print("Not a valid command.")
        except KeyboardInterrupt:
            print("\nExiting...")
            exit_secure_drop(current_user, [])
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    try:
        Register_choice = input('Do you want to register a new user (y/n)? ')
        if Register_choice.lower() == 'y':
            register_user()
            print('User Registered.')
            print('Exiting SecureDrop...')
            exit()
        else:
            user_login()
            print("End of program.")
    except KeyboardInterrupt:
        print("\nShutdown.")
        exit(0)