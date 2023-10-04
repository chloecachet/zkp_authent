import grpc
from src.proto import zkp_auth_pb2
from src.proto import zkp_auth_pb2_grpc
from src.zkp import ChaumPedersenExp

class Client:

    def __init__(self):
        self.zkp = ChaumPedersenExp()

    def buildRegisterRequest(self, user, password):
        """
        Generates a RegisterRequest message.
        @param user: username (string)
        @param password: user password(int)
        @rtype: RegisterRequest
        """
        y1, y2 = self.zkp.setup(password)
        return zkp_auth_pb2.RegisterRequest(user=user, y1=y1, y2=y2)

    def buildAuthenticationChallengeRequest(self, user):
        """
        Generates an AuthenticationChallengeRequest message.
        @param user: username (string)
        @rtype: int, AuthenticationChallengeRequest
        """
        k, r1, r2 = self.zkp.commitment()
        return k, zkp_auth_pb2.AuthenticationChallengeRequest(user=user, r1=r1, r2=r2)

    def buildAuthenticationAnswerRequest(self, user, password, challenge, commitment):
        """
        Generates an AuthenticationAnswerRequest message.
        @param user: username (string)
        @param password: user password(int)
        @param challenge: challenge received from server (int)
        @param commitment: commitment value chosen by client (int)
        @rtype: AuthenticationAnswerRequest
        """
        s = self.zkp.prove(commitment, challenge, password)
        return zkp_auth_pb2.AuthenticationAnswerRequest(auth_id=user, s=s)

    def register(self, user, password):
        """
        Client function to register new users.
        @param user: username (string)
        @param password: user password (int)
        @rtype: object
        """
        register_request = self.buildRegisterRequest(user, password)

        print("Registration attempt...")
        with grpc.insecure_channel("localhost:50051") as channel:
            stub = zkp_auth_pb2_grpc.AuthStub(channel)
            response = stub.Register(register_request)
        print("Registration complete.")

    def authenticate(self, user, password):
        """
        Client function handling user authentication.
        @param user: username (string)
        @param password: user password(int)
        """
        print("Authentication attempt...")

        k, auth_request = self.buildAuthenticationChallengeRequest(user)
        with grpc.insecure_channel("localhost:50051") as channel:
            stub = zkp_auth_pb2_grpc.AuthStub(channel)
            server_response = stub.CreateAuthenticationChallenge(auth_request)

            auth_request = self.buildAuthenticationAnswerRequest(user, password, server_response.c, k)
            server_response = stub.VerifyAuthentication(auth_request)

        if int(server_response.session_id) == -1:
            print("Authentication failed.")
        else:
            print("Authentication success ! Session id = " + str(server_response.session_id))

