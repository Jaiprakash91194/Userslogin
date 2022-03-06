import re
import pickle


# Conditions to create username & Password
def usernames_condition():
    print(""" 
    Conditions:
        - email/username should have "@" and followed by "."
        - there should not be any "." immediate next to "@"
        - it should not start with special characters and numbers           
        - Password conditions:
            - minimum one special character,
            - one digit,
            - one uppercase, 
            - one lowercase character
            """)


# Load the username directory from pickle file
def load_usernames():
    try:
        with open("usernames.pkl", "rb") as file:
            return pickle.load(file)
    except FileNotFoundError:
        return {}


# Function to dump dictionary to usernames directory
def dump_to_usernames(arg1):
    with open("usernames.pkl", "wb") as file:
        return pickle.dump(arg1, file)


# Check mail ID condition
def check_mail_address(arg1):
    pattern = "^[a-zA-Z].*@{1}[a-zA-Z0-9]+\.{1}[a-zA-Z0-9]"
    if re.match(pattern, arg1):
        return True
    else:
        return False


# Check password condition
def check_password(arg1):
    special_char = '.*[~!@#$%^&*()_{}:<>?/\|].*'
    digits = '.*[0-9].*'
    uppercase = '.*[A-Z].*'
    lowercase = '.*[a-z].*'
    if 5 <= len(arg1) <= 16:
        for match in (special_char, digits, uppercase, lowercase):
            if not re.search(match, arg1):
                return False
        return True
    return False


# Register if username doesn't exist
def registration():
    username = input("Please enter username:\n")
    password_input = input("Please enter password:\n")
    if check_mail_address(username):
        if check_password(password_input):
            usernames.update({username: password_input})
            dump_to_usernames(usernames)
        else:
            print("Password not valid")
            return False
    else:
        print("Username not valid")
        return False
    return True


# retrieve password if user requests
def retrieve_password(arg1):
    return usernames[arg1]


def main():
    # get input from user
    user_input = input("Do you want to login(Y/N)?\n")

    if user_input.upper() == "Y":
        username = input("Enter your mail ID:\n")
        if username in usernames:
            password = input("Enter password:\n")
            if password == usernames[username]:
                print("You have successfully logged in")
            else:
                forgot_password = input("Password doesn't match. Do you wanna retrieve your password?(Y/N)\n")
                if forgot_password.upper() == "Y":
                    print(retrieve_password(username))
                else:
                    print("Y not entered. Aborting")
        else:
            register = input("Looks like username doesn't exist. Do you want to Register(Y/N)?\n")
            if register.upper() == "Y":
                if not registration():
                    usernames_condition()
            else:
                print("Y not entered. Aborting")
    else:
        print("Y not entered. Aborting")


# load usernames directory to a variable
if __name__ == "__main__":
    main()
    usernames = load_usernames()
