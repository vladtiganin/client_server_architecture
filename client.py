import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, getFromatBytesFromMess,recvRawBytes
from src.utils.hashing import HashingSHA_256
from pydantic import BaseModel, PrivateAttr
from src.utils.AESfuncs import decrypedByAES, encrypedByAES
import os
from pathlib import Path


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


    def startComLoop(self):
        try:
            mode = (str(input("Enter mode: "))).upper()
        except Exception as ex:
            logger.exception("Error during get login data from user : ")

        try:
            match mode:
                case "PST":
                    self.sendPSTDta()
                case _:
                    raise ValueError("Invalid mode")
        except Exception as ex:
            logger.exception("Exeption during mode regis")


    def sendPSTDta(self) -> bytes:
        file_path = str(input("Enter file path: ")).strip()
        logger.info(f"input file path : {file_path}")

        path = Path(file_path)
        if not path.exists(): raise Exception("File does not exists")

        file_name = path.name
        logger.info(f"extracted file name : {file_name}")

        file_size = path.stat().st_size

        salt = HashingSHA_256.generate_salt(32)
        logger.debug(f"Salt : {salt}")
        file_data_hash = HashingSHA_256.hashingFile(path, salt)
        logger.debug(f"Hashed file data: {file_data_hash}")

        
        signature = RSA.encrypt_bytes_with_key(file_data_hash, self._rsa.private_key)

        # meta_data = (len(signature).to_bytes(4, 'big') +
        #              signature +
        #              len(file_name.encode).to_bytes(4, 'big') + 
        #              file_name.encode() +
        #              file_size.to_bytes(4, 'big'),
        # )

        meta_data = ( 
                     getFromatBytesFromMess(file_name) +
                     file_size.to_bytes(4, 'big')
                    )
        logger.debug(f"Meta data : {meta_data}")

        meta_data_encrypted = encrypedByAES(self._aes_key, meta_data)
        logger.debug(f"Meta data encrypted : {meta_data}")

        try:
            self._sock.sendall("PST".encode() + getFromatBytesFromMess(signature) + getFromatBytesFromMess(meta_data_encrypted))
        except Exception as ex:
            logger.exception("Exeption during sending meta data: ")


        self.startStream(path)


    def startStream(self, path: Path) -> None:
        MB = 1024 * 1024

        try:
            with open(path, "rb") as file:
                   while True:
                        chunck = file.read(MB)
                        if not chunck:
                           break
                        logger.debug(f"Chanck lenth {len(chunck)}")
                        chunck_enc = encrypedByAES(self._aes_key, chunck)
                        self._sock.sendall(getFromatBytesFromMess(chunck_enc))
        except Exception as ex:
            logger.exception("Error during streamig : ")

        logger.info("Streaming ends")     



if __name__ == "__main__":
    client = Client(
        host="localhost",
        port=9090
    )

    try:
        client.connect()
        client.AUTorREG()
        client.startComLoop()
    except Exception as ex:
        logger.exception("Error: ")
    finally:
        client.close_connection()