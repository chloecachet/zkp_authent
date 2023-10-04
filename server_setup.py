import logging
from src.server import Server

if __name__ == "__main__":
    logging.basicConfig()
    Server.serve()