import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, bigIntToBytes,recvRawBytes
from src.utils.hashing import HashingSHA_256
import json
from pydantic import BaseModel, PrivateAttr


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


class Client(BaseModel):
    host: str
    port: int
    _sock: socket.socket | None = PrivateAttr(default=None)
    _aes_key: bytes | None = PrivateAttr(default=None)


    def connect(self) -> None:
        logger.debug("Start working...")

        try:
            self._sock = socket.socket()
            self._sock.connect((self.host, self.port))
            self.get_session_key()
        except Exception as ex:
            logger.exception("Error during connecting to server: ")


    def close_connection(self) -> None:
        if self._sock:
            self._sock.close()
            logger.debug("End working...")
        else:
            logger.debug("Was no connection")


    def get_session_key(self) -> None:
        rsa = RSA()
        rsa.generate_keys(1024)

        data_to_send = self.__gengerate_data_to_send_RSAKey(rsa)

        try:
            self._sock.sendall(data_to_send)
            logger.debug("Send pk to server")
        except Exception as ex:
            logger.exception("Error during sending key: ")

        #далее нужно будет получить AES ключ

        aes_encr_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        logger.debug("Recive aes lenth")
        encrypt_aes_bytes = recvRawBytes(self._sock ,aes_encr_lenth)
        logger.debug("Recive AES key")
        aes__key = RSA.decrypt_bytes_with_key(encrypt_aes_bytes, rsa.private_key)
        logger.debug("Recive and decrypt AES key")

        sig_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        server_signature_bytes = recvRawBytes(self._sock ,sig_lenth)
        server_signature_bytes = RSA.decrypt_bytes_with_key(server_signature_bytes, rsa.private_key)
        logger.debug("Recive and decrypt server signature")


        if(HashingSHA_256.verifyHash(aes__key, server_signature_bytes)):
            self._aes_key = aes__key
        else: 
            logger.warning("Recived AES key hash doesnt equal to server signature hash")



    def __gengerate_data_to_send_RSAKey(self, rsa) -> bytes:

        public_key_bytes = getFormatBytesFromRSAKey(rsa.public_key)
        public_key_bytes_hash = HashingSHA_256.hashingBytes(public_key_bytes)
        client_signature = RSA.encrypt_bytes_with_key(public_key_bytes_hash, rsa.private_key)
        logger.debug(f"Encrypted signature length: {len(client_signature)}")

        send_data = (public_key_bytes +
                    len(client_signature).to_bytes(4,'big')+
                    client_signature)
        logger.debug(f"RSA pk data : {send_data}")
        
        return send_data


if __name__ == "__main__":
    client = Client(
        host="localhost",
        port=9090
    )

    client.connect()

    client.close_connection()