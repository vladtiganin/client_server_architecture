import socket
import logging

logger = logging.Logger(name="client")
logger.setLevel(logging.INDEBUGFO)

handler = logging.FileHandler(f"logs/client.log", "w")
formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)


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