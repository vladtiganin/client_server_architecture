import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, getFromatBytesFromMess,recvRawBytes
from src.utils.hashing import HashingSHA_256
from pydantic import BaseModel, PrivateAttr
from src.utils.AESfuncs import decrypedByAES, encrypedByAES


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


class Client(BaseModel):
    host: str
    port: int
    _sock: socket.socket | None = PrivateAttr(default=None)
    _aes_key: bytes | None = PrivateAttr(default=None)
    _rsa: RSA | None = PrivateAttr(default=None)


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
        self._rsa = RSA()
        self._rsa.generate_keys(1024)

        data_to_send = self.__gengerate_data_to_send_RSAKey()

        try:
            self._sock.sendall(data_to_send)
            logger.debug("Send pk to server")
        except Exception as ex:
            logger.exception("Error during sending key: ")

        aes_encr_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        encrypt_aes_bytes = recvRawBytes(self._sock ,aes_encr_lenth)
        aes__key = RSA.decrypt_bytes_with_key(encrypt_aes_bytes, self._rsa.private_key)
        logger.debug("Recive and decrypt AES key")

        sig_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        server_signature_bytes = recvRawBytes(self._sock ,sig_lenth)
        server_signature_bytes = RSA.decrypt_bytes_with_key(server_signature_bytes, self._rsa.private_key)
        logger.debug("Recive and decrypt server signature")


        if(HashingSHA_256.verifyHash(aes__key, server_signature_bytes)):
            self._aes_key = aes__key
        else: 
            logger.error("Recived AES key hash doesnt equal to server signature hash")
            raise Exception


    def createSignature(self, data: tuple[bytes]) -> bytes:
        data_bytes = b''
        for dat in data: data_bytes =  data_bytes + dat

        data_hash = HashingSHA_256.hashingBytes(data_bytes)
        signature = RSA.encrypt_bytes_with_key(data_hash, self._rsa.private_key)
        return signature


    def __gengerate_data_to_send_RSAKey(self) -> bytes:

        public_key_bytes = getFormatBytesFromRSAKey(self._rsa.public_key)
        client_signature = self.createSignature((public_key_bytes,))
        logger.debug(f"Encrypted signature length: {len(client_signature)}")

        send_data = (public_key_bytes +
                    len(client_signature).to_bytes(4,'big')+
                    client_signature)
        logger.debug(f"RSA pk data : {send_data}")
        
        return send_data


    def AUTorREG(self):
        try:
            mode = (str(input("AUT or REG: "))).upper().encode()
            login = str(input("Enter your login: "))
            password = str(input("Enter your password: "))
        except Exception as ex:
            logger.exception("Error during get login data from user : ")

        signature = self.createSignature((login.encode(), password.encode()))
        logger.debug(f"Client AUT signature: {signature}")

        lp_bytes = getFromatBytesFromMess(login) + getFromatBytesFromMess(password)
        lp_bytes_encryped = encrypedByAES(self._aes_key, lp_bytes)

        send_data = (mode +
                     len(signature).to_bytes(4, 'big') +
                     signature +
                     len(lp_bytes_encryped).to_bytes(4, 'big') +
                     lp_bytes_encryped)
        
        try:
            self._sock.sendall(send_data)
        except Exception as es:
            logger.exception("Error during sending AUT or REG message: ")


if __name__ == "__main__":
    client = Client(
        host="localhost",
        port=9090
    )

    try:
        client.connect()
        client.AUTorREG()
    except Exception as ex:
        logger.exception("Error: ")
    finally:
        client.close_connection()