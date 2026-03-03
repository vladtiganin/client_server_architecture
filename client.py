import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, bigIntToBytes


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


def main():
    logger.debug("Start working...")

    try:
        sock = socket.socket()
        sock.connect(("localhost", 9090))
    except Exception as ex:
        logger.exception("Error during connecting to server: ")

    rsa = RSA()
    rsa.generate_keys(1024)

    public_key_bytes = getFormatBytesFromRSAKey(rsa.public_key)
    try:
        sock.sendall(public_key_bytes)
    except Exception as ex:
        logger.exception("Error during sending key: ")



    logger.debug(rsa.public_key.first)
    logger.debug(rsa.public_key.second)

    # user_str = input("Enter: ")
    # sock.send(user_str.encode())
    # data = sock.recv(1024)

    # print(data.decode())

    sock.close()
    logger.debug("End working...")



if __name__ == "__main__":
    main()