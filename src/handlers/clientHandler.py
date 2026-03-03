import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSAKey
from src.utils.bytesFuncs import getRSAKeyFromBytes

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def clientHandler(conn):

    client_public_key = getRSAKeyFromBytes(sock=conn)
    logger.debug(f"Recive public_key")
    logger.debug(f"First part: {client_public_key.first}")
    logger.debug(f"Second part: {client_public_key.second}")
