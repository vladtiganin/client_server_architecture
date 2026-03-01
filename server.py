import threading
import socket
import logging

logger = logging.Logger(name=__name__)
logger.setLevel(logging.INFO)

handler = logging.FileHandler(f"{__name__}.log", "w")
formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)


def main():
    logger.debug("Start working...")
    sock = socket.socket()

    sock.bind(("localhost", 9090))
    sock.listen(3)

    


if __name__ == "__main__":
    main()
