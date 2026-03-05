import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSAKey
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getRSAKeyFromBytes, recvRawBytes, getFormatBytesFromRSAKey
from src.utils.hashing import HashingSHA_256
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
import socket

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


class ClientHandler():
    def __init__(self, conn : socket.socket):
        if conn is None : raise ValueError("Empty socket")
        self.conn = conn
        self._client_pubk = None
        self.aes_key = None

    
    def handshake(self):
        self._client_pubk = getRSAKeyFromBytes(self.conn)
        logger.debug(f"Client public key first part : {self._client_pubk.first}")
        logger.debug(f"Client public key second part : {self._client_pubk.second}")

        client_signature_bytes =  self.__recive_signature()

        if not HashingSHA_256.verifyHashRSAKey(self._client_pubk, client_signature_bytes): 
            raise ValueError("Recived data was modifide")

        self.__generateAES()
        logger.debug(f"AES : {self,self.aes_key}")

        data_to_send = self.__generateAESExchangeMess()
        logger.debug(f"Data to exchenge aes key with client : {data_to_send}")
        
        try:
            self.conn.sendall(data_to_send)
        except Exception as ex:
            logger.exception("Something goes wrong during eas exchenge : ")



    def __recive_signature(self) -> bytes:
        sig_lenth = int.from_bytes(recvRawBytes(self.conn, 4), 'big')
        signature = recvRawBytes(self.conn, sig_lenth)
        signature = RSA.decrypt_bytes_with_key(signature, self._client_pubk, 64)
        logger.debug(f"Decrypted signature length: {len(signature)}")
        logger.debug(f"Decrypted signature: {signature}")
        return signature
    

    def __generateAES(self):
        self.aes_key = get_random_bytes(32)


    def __generateAESExchangeMess(self) -> bytes:
        aes_key_hash = HashingSHA_256.hashingBytes(self.aes_key)
        server_signature_bytes = RSA.encrypt_bytes_with_key(aes_key_hash, self._client_pubk)
        sig_lenth = len(server_signature_bytes).to_bytes(4, 'big')
        encrypt_aes_bytes = RSA.encrypt_bytes_with_key(self.aes_key, self._client_pubk)
        aes_encr_lenth = len(encrypt_aes_bytes).to_bytes(4, 'big')

        data_to_send = (aes_encr_lenth +
                        encrypt_aes_bytes +
                        sig_lenth +
                        server_signature_bytes)
        
        return data_to_send


def clientHandler(conn):
    logger.debug("Start handle client")

    handler = ClientHandler(conn)
    handler.handshake()

    logger.debug("End handle client") 