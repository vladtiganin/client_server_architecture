import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, bigIntToBytes
from src.utils.hashing import HashingSHA_256
import json
from pydantic import BaseModel, PrivateAttr


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


class Client(BaseModel):
    host: str
    port: int
    _sock: socket.socket | None = PrivateAttr(default=None)


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

        data_to_send = self.__gengerateDataToSendRSAKey(rsa)

        try:
            self._sock.sendall(data_to_send)
        except Exception as ex:
            logger.exception("Error during sending key: ")

        #далее нужно будет получить AES ключ


    def __gengerateDataToSendRSAKey(self, rsa) -> bytes:

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