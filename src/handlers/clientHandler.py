import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSAKey
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getRSAKeyFromBytes, recvRawBytes, getFormatBytesFromRSAKey
import json
from src.utils.hashing import HashingSHA_256
from pydantic import BaseModel, PrivateAttr
import socket

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


class ClientHandler():
    def __init__(self, conn):
        if conn is None : raise ValueError("Empty socket")
        self.conn = conn
        self._client_pubk = None
        self.aes_key = None

    
    def handshake(self):
        self._client_pubk = getRSAKeyFromBytes(self.conn)
        logger.debug(f"Client public key first part : {self._client_pubk.first}")
        logger.debug(f"Client public key second part : {self._client_pubk.second}")

        signature_bytes =  self.__recive_signature()

        if(HashingSHA_256.verifyHash(self._client_pubk, signature_bytes)): 
            print("good")
        else: 
            print("No") 

        # далее вообще обмен AES ключаеми



    def __recive_signature(self) -> bytes:
        sig_lenth = int.from_bytes(recvRawBytes(self.conn, 4), 'big')
        signature = recvRawBytes(self.conn, sig_lenth)
        signature = RSA.decrypt_bytes_with_key(signature, self._client_pubk, 64)
        logger.debug(f"Decrypted signature length: {len(signature)}")
        logger.debug(f"Decrypted signature: {signature}")
        return signature


def clientHandler(conn):
    logger.debug("Start handle client")

    handler = ClientHandler(conn)
    handler.handshake()

    logger.debug("End handle client") 