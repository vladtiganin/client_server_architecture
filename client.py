import socket
import logging
from src.utils import createLogger
import os, sys
from src.utils.RSA import rsa_core


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


def main():
    # logger.debug("Start working...")
    # sock = socket.socket()
    # sock.connect(("localhost", 9090))

    # user_str = input("Enter: ")
    # sock.send(user_str.encode())
    # data = sock.recv(1024)

    # print(data.decode())

    # sock.close()
    # logger.debug("End working...")

    rsa = rsa_core.RSA()
    rsa.generate_keys()
    print("Публичный ключ (e, N):", rsa.public_key.first, rsa.public_key.second, sep='\n')
    print("Приватный ключ (d, N):", rsa.private_key.first, rsa.private_key.second, sep='\n')


if __name__ == "__main__":
    main()