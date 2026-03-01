import logging

logger = logging.Logger(name=__name__)
logger.setLevel(logging.DEBUG)

handler = logging.FileHandler(f"logs/{__name__}.log", "w")
formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)

def clientHandler(conn):
    data = conn.recv(1024)
    conn.send(data.upper())