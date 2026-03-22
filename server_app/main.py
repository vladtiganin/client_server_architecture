from __future__ import annotations

import logging
import socket
import threading

from server_app.config import BACKLOG, BIND_HOST, PORT, SOCKET_TIMEOUT
from server_app.crypto import create_logger
from server_app.handlers import clientHandler


logger = create_logger("server")
logger.setLevel(logging.DEBUG)


def main() -> None:
    logger.debug("Start working...")
    sock = socket.socket()
    sock.bind((BIND_HOST, PORT))
    sock.listen(BACKLOG)
    sock.settimeout(SOCKET_TIMEOUT)

    connections = []
    try:
        while True:
            try:
                conn, addr = sock.accept()
                logger.info("Connected: %s", addr)
            except TimeoutError:
                continue

            thread = threading.Thread(target=clientHandler, args=(conn,), daemon=True)
            thread.start()
            connections.append({"connection": conn, "thread": thread, "address": addr})
    except KeyboardInterrupt:
        logging.info("Server stopped by user")
    except Exception:
        logging.exception("Error")
    finally:
        for conn_info in connections:
            conn_info["thread"].join()
        sock.close()

    logger.debug("End working...")


if __name__ == "__main__":
    main()
