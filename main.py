import json
import os

USERS_FILE = "users.json"

def print_commands():
    print("add\nhelp\nsend\nlist\nexit\n")
    return
def file_send(current_user, args):
    if len(args) < 2:
        print("Command format is send <email address> <filename> ")
    target_email, file_name = args
    print(f"Sending {file_name} to {target_email}...")
    return 0
def online_list():
    return []
def exit_secure_drop():
    return False


def load_users():
    # Load all users from json file (if file exists)
    if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
        return[]
   
    with open(USERS_FILE, "r") as file:
        return json.load(file)

def save_users(users):

    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)

def email_exists(users, email):
    return any(user["email address"] == email for user in users)

users = load_users()       # global scope

def register_user():
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

    users[Regemail] = {
    "name": RegnameInput,
    "password": Regpassword,
    "contacts": [],
    "Pending Request": []
    }
    save_users(users)
    user_login()

# helper func for contact reguests
def send_request(sender_email, args):
    if len(args) < 1:
        print("Command format is "'add'" <email address>" )
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
    while True:
        email_login = input("Enter email address: ")
        password_login = input("Enter your password: ")

        if email_login in users and password_login == users[email_login]["password"]:
            print("Login Successful")
            user_menu(email_login)
        else:
            print("Email and password combination not valid")

    

def user_menu(current_user):
    print(f"Welcome to SecureDrop!\nType "'help'" for commands")
    running = True
    while running:
        user_input = input("> ").strip()  # strip just removes leading/trialing whitespaces
        if not user_input:
            continue
        parts = user_input.split()      # split input into cmd and there arguments for that cmd
        cmd, *args = parts
        if cmd in commands:
            result = commands[cmd](current_user, args)
            if result is False:
                running = False

        else:
            print(f"Not valid command. ")

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