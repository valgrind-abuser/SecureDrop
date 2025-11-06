import json
import os

USERS_FILE = "users.json"

def print_commands():
    print("add\nhelp\nsend\n ist\nexit\n")
    return
def file_send(target_email):
    print("Sending file...")
    return 0
def online_list():
    return []
def exit_secure_drop():
    exit()


def load_users():
    # Load all users from json file (if file exists)
    if not os.path.exists(USERS_FILE):
        return[]
    if os.path.getsize(USERS_FILE) == 0:
        return []
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

        if email_exists(users, Regemail):
            print("This user is already registered. Please use different email address. ")
            exit()
            
        Regpassword = input("Enter password: ")
        Regpassword2 = input("Re-enter password: ")
        if Regpassword == Regpassword2:
            print("Passwords Match. ")
            break
        else:
            print("Passwords Did Not Match. Please Try Again. ")

    new_user = {
    "name": RegnameInput,
    "email address": Regemail,
    "password": Regpassword,
    "contacts": [],
    "Pending Request": []
    }
    users.append(new_user)
    save_users(users)

# helper func for contact reguests
def send_request(sender_email, target_email):
    if target_email not in users:
        print("User not found. ")
        return
    if sender_email in users[target_email]["Pending Request"]:
        print(f"Already sent friend request to {target_email}. ")
        return
    users[target_email]["Pending Request"].append(sender_email)
    print(f"Friend request sent to {target_email}. ")
  
commands = {
    "add": send_request,
    "help": print_commands,
    "send": file_send,
    "list": online_list,
    "exit": exit_secure_drop
}

def user_menu():
    print(f"Welcome to SecureDrop!\nType "'help'" for commands")
    user_input = input("").strip()
    if user_input in commands:
        result = commands[user_input]()
       
    else:
        print(f"Not valid command. ")


Register_choice = input('Do you want to register a new user (y/n)? ')
if Register_choice == 'Y' or Register_choice == 'y':
        register_user()
        print('User Registered.')
        print('Exiting SecureDrop...')
        exit()
else:
    user_menu()