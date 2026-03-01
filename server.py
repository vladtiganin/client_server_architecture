import threading
import socket
import logging
from src.handlers import clientHandler


logger = logging.Logger(name="server")
logger.setLevel(logging.DEBUG)

handler = logging.FileHandler(f"logs/server.log", "w")
formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)


def main():
    logger.debug("Start working...")
    sock = socket.socket()

    sock.bind(("localhost", 9090))
    sock.listen(3)
    sock.settimeout(1)

    connections = []
    try:
        while(True):
            try:
                conn, addr = sock.accept()
                logger.info(f"Connected: {addr}")
            except TimeoutError: continue

            thread = threading.Thread(target=clientHandler, args=(conn,), daemon=True)
            thread.start()
            logger.debug("Create new thread")

            connections.append({
                "connection" : conn,
                "thread" : thread,
                "address" : addr
            })
    except KeyboardInterrupt as ex:
        logging.info("Server stoped by user")
    except Exception as ex:
        logging.exception("Error")
    finally:
        for conn_info in connections:
            conn_info["thread"].join()
        sock.close()

    
    logger.debug("End working...")



if __name__ == "__main__":
    main()
