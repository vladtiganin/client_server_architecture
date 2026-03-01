import socket
import logging
from src.utils import createLogger


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


def main():
    logger.debug("Start working...")
    sock = socket.socket()
    sock.connect(("localhost", 9090))

    user_str = input("Enter: ")
    sock.send(user_str.encode())
    data = sock.recv(1024)

    print(data.decode())

    sock.close()
    logger.debug("End working...")


if __name__ == "__main__":
    main()