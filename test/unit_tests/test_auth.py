import unittest
from src.client import Client
from src.server import Server



class Authentication(unittest.TestCase):

    def test_register_new_user(self):
        print("TEST: new user registration")
        client = Client()
        server = Server()

        client_query = client.buildRegisterRequest("steve", 6)
        server_response = server.Register(client_query, None)

    def test_register_known_user(self):
        print("TEST: known user registration")
        client = Client()
        server = Server()

        client_query = client.buildRegisterRequest("bob", 6)
        server_response = server.Register(client_query, None)

    def test_auth_success(self):
        print("TEST: authentication success")
        client = Client()
        server = Server()

        user = "bob"
        password = 6

        client_commit, client_query = client.buildAuthenticationChallengeRequest(user)
        server_challenge = server.CreateAuthenticationChallenge(client_query, None)
        # print("Server challenge = " + str(server_challenge.c))
        print("Auth id = " + server_challenge.auth_id)

        client_query = client.buildAuthenticationAnswerRequest(user, password, server_challenge.c, client_commit)
        server_response = server.VerifyAuthentication(client_query, None)

        print("Session id = " + server_response.session_id)
        self.assertNotEqual(int(server_response.session_id), 0)
        self.assertNotEqual(int(server_response.session_id), -1)

    def test_auth_invalid_user(self):
        print("TEST: authentication failure (invalid user)")
        client = Client()
        server = Server()

        user = "steve"
        password = 6

        client_commit, client_query = client.buildAuthenticationChallengeRequest(user)
        server_challenge = server.CreateAuthenticationChallenge(client_query, None)
        # print("Server challenge = " + str(server_challenge.c))

        client_query = client.buildAuthenticationAnswerRequest(user, password, server_challenge.c, client_commit)
        server_response = server.VerifyAuthentication(client_query, None)

        print("Session id = " + server_response.session_id)
        self.assertEqual(int(server_response.session_id), -1)

    def test_auth_invalid_pwd(self):
        print("TEST: authentication failure (invalid password)")
        client = Client()
        server = Server()

        user = "bob"
        password = 7

        client_commit, client_query = client.buildAuthenticationChallengeRequest(user)
        server_challenge = server.CreateAuthenticationChallenge(client_query, None)
        # print("Server challenge = " + str(server_challenge.c))

        client_query = client.buildAuthenticationAnswerRequest(user, password, server_challenge.c, client_commit)
        server_response = server.VerifyAuthentication(client_query, None)

        print("Session id = " + server_response.session_id)
        self.assertEqual(int(server_response.session_id), -1)


if __name__ == '__main__':
    unittest.main()