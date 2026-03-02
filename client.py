import socket
import logging
from src.utils import createLogger
from src.utils.RSA import rsa_core
from src.utils.bytes_big_int import bigIntToBytes, bytesToBigInt


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


def main():
    logger.debug("Start working...")

    try:
        sock = socket.socket()
        sock.connect(("localhost", 9090))
    except Exception as ex:
        logger.exception("Error during connecting to server: ")

    rsa = rsa_core.RSA()
    rsa.generate_keys()
    print(len(bigIntToBytes(rsa.public_key.first)))
    print(len(bigIntToBytes(rsa.public_key.second)))

    # user_str = input("Enter: ")
    # sock.send(user_str.encode())
    # data = sock.recv(1024)

    # print(data.decode())

    sock.close()
    logger.debug("End working...")



if __name__ == "__main__":
    main()