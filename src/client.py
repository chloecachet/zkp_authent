import grpc
from src.proto import zkp_auth_pb2
from src.proto import zkp_auth_pb2_grpc
import logging
from src.zkp import ChaumPedersenExp

class Client:

    def __init__(self):
        self.zkp = ChaumPedersenExp()

    def buildRegisterRequest(self, user, password):
        # compute y1 and y2 for Chaum-Pedersen ZKP
        y1, y2 = self.zkp.setup(password)

        return zkp_auth_pb2.RegisterRequest(user=user, y1=y1, y2=y2)

    def buildAuthenticationChallengeRequest(self, user):
        k, r1, r2 = self.zkp.commitment()
        return k, zkp_auth_pb2.AuthenticationChallengeRequest(user=user, r1=r1, r2=r2)

    def buildAuthenticationAnswerRequest(self, user, password, challenge, commitment):
        s = self.zkp.prove(commitment, challenge, password)
        return zkp_auth_pb2.AuthenticationAnswerRequest(auth_id=user, s=s)

    def register(self, user, password):
        register_request = self.buildRegisterRequest(user, password)

        print("Registration attempt...")
        with grpc.insecure_channel("localhost:50051") as channel:
            stub = zkp_auth_pb2_grpc.AuthStub(channel)
            response = stub.Register(register_request)
        print("Registration completed: " + response.message)

    def authenticate(self, user, password):
        print("Authentication attempt...")

        k, auth_request = self.buildAuthenticationChallengeRequest(user)
        with grpc.insecure_channel("localhost:50051") as channel:
            stub = zkp_auth_pb2_grpc.AuthStub(channel)
            server_response = stub.CreateAuthenticationChallenge(auth_request)

        auth_request = self.buildAuthenticationAnswerRequest(user, password, server_response.c, k)
        with grpc.insecure_channel("localhost:50051") as channel:
            stub = zkp_auth_pb2_grpc.AuthStub(channel)
            server_response = stub.VerifyAuthentication(auth_request)

        if int(server_response.session_id) == -1:
            print("Authentication failed.")
        else:
            print("Authentication success ! Session id = " + str(1))



if __name__ == "__main__":
    logging.basicConfig()
    client = Client()

    user_input = input("To register new user type R, to authenticate type A")
    user = input("Please write user name:")
    password = input("Please write password:")

    if user_input == "R":
        client.register(user, password)
    elif user_input == "A":
        client.authenticate(user, password)
    else:
        print("Invalid input")
