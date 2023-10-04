import logging
from src.client import Client

if __name__ == "__main__":
    logging.basicConfig()
    client = Client()

    user_input = input("To register new user type R, to authenticate type A")
    user = input("Please write user name:")
    password = input("Please write password:")

    if user_input == "R":
        client.register(user, int(password))
    elif user_input == "A":
        client.authenticate(user, int(password))
    else:
        print("Invalid input")