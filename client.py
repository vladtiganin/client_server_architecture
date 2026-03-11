import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, getFromatBytesFromMess,recvRawBytes, createSignature, reciveSignature
from src.utils.hashing import HashingSHA_256
from pydantic import BaseModel, PrivateAttr
from src.utils.AESfuncs import decrypedByAES, encrypedByAES
import os
from src.utils.streamFunc import startStream, recvStreaming, recvStreamingToFileAndVerify
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


    def __gengerate_data_to_send_RSAKey(self) -> bytes:

        public_key_bytes = getFormatBytesFromRSAKey(self._rsa.public_key)
        client_signature = createSignature(self._rsa.private_key, (public_key_bytes,))
        logger.debug(f"Encrypted signature length: {len(client_signature)}")

        send_data = (public_key_bytes +
                    len(client_signature).to_bytes(4,'big')+
                    client_signature)
        logger.debug(f"RSA pk data : {send_data}")
        
        return send_data


    @staticmethod
    def vlidateLogin(login : str):
        if login == '' : raise ValueError("Invalid login : empty")
        if len(login) < 4 : raise ValueError("Invalid login : lenth of login must be more then 4") 
        return login


    @staticmethod
    def vlidatePassword(password: str):
        if password == '' : raise ValueError("Invalid password : empty")
        if len(password) < 4 : raise ValueError("Invalid password : lenth of password must be more then 4") 
        return password


    def AUTorREG(self):
        mode = (str(input("AUT or REG: "))).upper().encode()
        if mode not in ("AUT".encode(), "REG".encode()) : raise ValueError("Invalid mode input")

        login = Client.vlidateLogin(str(input("Enter your login: ")).strip())
        password = Client.vlidatePassword(str(input("Enter your password: ")).strip())


        signature = createSignature(self._rsa.private_key, (login.encode(), password.encode()))
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
        mode = (str(input("Enter mode: "))).upper()
        match mode:
            case "PST":
                self.sendData()
            case "LIS":
                self.listData()
            case "GET":
                self.getFile()
            case _:
                raise ValueError("Invalid mode")



    def getFile(self):
        file_name = str(input("Enter file name you want to download : ")).encode()

        file_name_encr = encrypedByAES(self._aes_key, file_name)
        logger.info("File name encrypted")

        signature = createSignature(self._rsa.private_key, (file_name, ))
        logger.info("Signature created")

        self._sock.sendall("GET".encode() + 
                           getFromatBytesFromMess(signature) + 
                           getFromatBytesFromMess(file_name_encr))
        logger.info("Get request sent")


        signature = reciveSignature(self._sock, self._rsa.private_key)
        logger.info("Signature recived")

        file_name_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        file_name = decrypedByAES(self._aes_key, recvRawBytes(self._sock, file_name_lenth)).decode()
        logger.info(f"File name recived : {file_name}")

        file_size_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        file_size = decrypedByAES(self._aes_key, recvRawBytes(self._sock, file_size_lenth)).decode()
        logger.info(f"File size recived : {file_size}")


        recv_file_path = Path(r"temp.txt")
        result = recvStreamingToFileAndVerify(self._sock, self._aes_key, recv_file_path, signature)
        
        if result :print("good")
        else : print("No") 

        # data = recvStreaming(self._sock, self._aes_key)
        # logger.info("Data recived")
        # logger.debug(f"Data lenth : {len(data)} bytes")
        # logger.debug(f"data : {data}")

        # if not HashingSHA_256.verifyHash(data, signature) : raise ValueError("Recived data does not verified")
        # print("good")



    def sendData(self):
        file_path = str(input("Enter file path: ")).strip()
        if file_path == '': raise ValueError("File path is empty")
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

        meta_data = (getFromatBytesFromMess(file_name) +
                     file_size.to_bytes(4, 'big'))
        logger.debug(f"Meta data : {meta_data}")

        meta_data_encrypted = encrypedByAES(self._aes_key, meta_data)
        logger.debug(f"Meta data encrypted : {meta_data}")

        self._sock.sendall("PST".encode() + 
                           getFromatBytesFromMess(signature) + 
                           getFromatBytesFromMess(meta_data_encrypted))


        startStream(self._aes_key, self._sock, path)


    def listData(self):
        self._sock.send("LIS".encode())

        signature = reciveSignature(self._sock, self._rsa.private_key)

        tuple_lenth = int.from_bytes(recvRawBytes(self._sock, 4), 'big')
        names_tuple = eval(decrypedByAES(self._aes_key, recvRawBytes(self._sock, tuple_lenth)).decode())
        logger.info("Recive names tuple")
        logger.debug(f"Names tuple : {names_tuple}")

        print(names_tuple)



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