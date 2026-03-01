import logging
from src.utils import createLogger

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def clientHandler(conn):
    data = conn.recv(1024)
    conn.send(data.upper())