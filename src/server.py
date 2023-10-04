from concurrent import futures
from src.zkp import ChaumPedersenExp
import grpc
from src.proto import zkp_auth_pb2
from src.proto import zkp_auth_pb2_grpc
import secrets


class ServerState:
    def __init__(self, auth_id, user, r1, r2, challenge):
        self.auth_id = auth_id
        self.session_id = ""
        self.user = user
        self.r1 = r1
        self.r2 = r2
        self.c = challenge


class Server(zkp_auth_pb2_grpc.AuthServicer):
    #TODO use db instead of dict
    def __init__(self):
        self.userdb = {
                          "bob": (2, 3),
                          "alice": (6, 8),
                          "eve": (5, 8)
                        }

    def Register(self, request, context):
        """
        Server's function to register new users. Adds user/(y1,y2) to userdb if user is new.
        @param request: client request message (RegisterRequest)
        @param context:
        @rtype: RegisterResponse
        """
        if request.user in self.userdb:
            print("User already registered.")
            return zkp_auth_pb2.RegisterResponse()
        else:
            print("Registering new user " + request.user)
            self.userdb[request.user] = (request.y1, request.y2)
            return zkp_auth_pb2.RegisterResponse()


    def CreateAuthenticationChallenge(self, request, context):
        """
        Server's function to start authentication process and generate challenge required for Chaum-Pedersen ZKP.
        @param request: client request message (AuthenticationChallengeRequest)
        @param context:
        @rtype: AuthenticationChallengeResponse
        """
        zkp = ChaumPedersenExp()
        challenge = zkp.challenge()
        auth_id = "1"
        self.state = ServerState(auth_id, request.user, request.r1, request.r2, challenge)
        return zkp_auth_pb2.AuthenticationChallengeResponse(auth_id=auth_id, c=challenge)

    def VerifyAuthentication(self, request, context):
        """
        Server's function to verify authentication.
        Session ID of -1 indicates authentication failure (either invalid user or invalid password).
        Authentication success will result in random 256 bits session id to be used as token for future interactions.
        @param request: client request message (AuthenticationAnswerRequest)
        @param context:
        @rtype: AuthenticationAnswerResponse
        """
        zkp = ChaumPedersenExp()

        if self.state.user in self.userdb:
            y1, y2 = self.userdb[self.state.user]
            result = zkp.verify(y1, y2, self.state.r1, self.state.r2, self.state.c, request.s)
        else:
            result = False

        if result:
            self.state.session_id = str(secrets.randbits(256))
        else:
            self.state.session_id = str(-1)

        return zkp_auth_pb2.AuthenticationAnswerResponse(session_id=self.state.session_id)

    @staticmethod
    def run():
        port = "50051"
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        zkp_auth_pb2_grpc.add_AuthServicer_to_server(Server(), server)
        server.add_insecure_port("[::]:" + port)
        server.start()
        print("Server started, listening on " + port)


    @staticmethod
    def serve():
        """
        Static function to run authentication server service on port 50051.
        """
        port = "50051"
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        zkp_auth_pb2_grpc.add_AuthServicer_to_server(Server(), server)
        server.add_insecure_port("[::]:" + port)
        server.start()
        print("Server started, listening on " + port)
        server.wait_for_termination()


