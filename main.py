import json
import os

USERS_FILE = "users.json"

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

def register_user():
    users = load_users()

    while True:
        RegnameInput = input("Enter Full Name: ")
        Regemail = input("Enter email address: ")

        if email_exists(users, Regemail):
            print("This user is already registered. Please use different email address. ")
            exit();
            
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
    "password": Regpassword
    }
    users.append(new_user)
    save_users(users)
    

Register_choice = input('Do you want to register a new user (y/n)? ')
if Register_choice == 'Y' or Register_choice == 'y':
        register_user()
        print('User Registered.')
        print('Exiting SecureDrop...')
        exit()






