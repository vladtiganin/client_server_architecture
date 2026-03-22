from __future__ import annotations

import logging
import socket
from ast import literal_eval
from pathlib import Path

from pydantic import BaseModel, PrivateAttr

from client_app.RSA import RSA
from client_app.config import DEFAULT_HOST, DEFAULT_PORT
from client_app.crypto import (
    HashingSHA_256,
    create_logger,
    create_signature,
    decrypedByAES,
    encrypedByAES,
    get_format_bytes_from_message,
    get_format_bytes_from_rsa_key,
    receive_signature,
    recv_raw_bytes,
    recvStreamingToFileAndVerify,
    startStream,
)


logger = create_logger("client")
logger.setLevel(logging.DEBUG)


class Client(BaseModel):
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    _sock: socket.socket | None = PrivateAttr(default=None)
    _aes_key: bytes | None = PrivateAttr(default=None)
    _rsa: RSA | None = PrivateAttr(default=None)

    def connect(self) -> bool:
        logger.debug("Start working...")

        try:
            self._sock = socket.socket()
            self._sock.connect((self.host, self.port))
            self.get_session_key()
            return True
        except Exception:
            logger.exception("Error during connecting to server")
            return False

    def close_connection(self) -> None:
        if self._sock:
            self._sock.close()
            logger.debug("End working...")
        else:
            logger.debug("Was no connection")

    def get_session_key(self) -> None:
        self._rsa = RSA()
        self._rsa.generate_keys(1024)

        data_to_send = self.__generate_data_to_send_rsa_key()
        self._sock.sendall(data_to_send)
        logger.debug("Send public key to server")

        aes_encrypted_length = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        encrypted_aes_bytes = recv_raw_bytes(self._sock, aes_encrypted_length)
        aes_key = RSA.decrypt_bytes_with_key(encrypted_aes_bytes, self._rsa.private_key)
        logger.debug("Receive and decrypt AES key")

        signature_length = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        server_signature_bytes = recv_raw_bytes(self._sock, signature_length)
        server_signature_bytes = RSA.decrypt_bytes_with_key(server_signature_bytes, self._rsa.private_key)
        logger.debug("Receive and decrypt server signature")

        if HashingSHA_256.verifyHash(aes_key, server_signature_bytes):
            self._aes_key = aes_key
            return

        logger.error("Received AES key hash does not match server signature")
        raise ValueError("Server handshake verification failed")

    def __generate_data_to_send_rsa_key(self) -> bytes:
        public_key_bytes = get_format_bytes_from_rsa_key(self._rsa.public_key)
        client_signature = create_signature(self._rsa.private_key, (public_key_bytes,))

        return public_key_bytes + len(client_signature).to_bytes(4, "big") + client_signature

    @staticmethod
    def vlidateLogin(login: str) -> str:
        if login == "":
            raise ValueError("Invalid login: empty")
        if len(login) < 4:
            raise ValueError("Invalid login: length of login must be at least 4")
        return login

    @staticmethod
    def vlidatePassword(password: str) -> str:
        if password == "":
            raise ValueError("Invalid password: empty")
        if len(password) < 4:
            raise ValueError("Invalid password: length of password must be at least 4")
        return password

    def getAUTorREGData(self) -> tuple[str, str, str]:
        mode = str(input("AUT or REG: ")).upper()
        if mode not in ("AUT", "REG"):
            raise ValueError("Invalid mode input")

        login = Client.vlidateLogin(str(input("Enter your login: ")).strip())
        password = Client.vlidatePassword(str(input("Enter your password: ")).strip())

        return mode, login, password

    def AUTorREG(self, mode=None, login=None, password=None):
        if mode is None and login is None and password is None:
            mode, login, password = self.getAUTorREGData()

        signature = create_signature(self._rsa.private_key, (login.encode(), password.encode()))
        lp_bytes = get_format_bytes_from_message(login) + get_format_bytes_from_message(password)
        lp_bytes_encrypted = encrypedByAES(self._aes_key, lp_bytes)

        send_data = (
            mode.encode()
            + len(signature).to_bytes(4, "big")
            + signature
            + len(lp_bytes_encrypted).to_bytes(4, "big")
            + lp_bytes_encrypted
        )

        self._sock.sendall(send_data)
        return self.reciveResonse()

    def reciveResonse(self):
        code = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        body_length = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        body = recv_raw_bytes(self._sock, body_length)
        body = literal_eval(decrypedByAES(self._aes_key, body).decode())
        if not body["success"]:
            logger.info('Error during request: %s', body["message"])
        return code, body

    def startComLoop(self):
        mode = str(input("Enter mode: ")).upper()
        match mode:
            case "PST":
                self.sendData()
            case "LIS":
                self.listData()
            case "GET":
                self.getFile()
            case "DEL":
                self.delFile()
            case _:
                raise ValueError("Invalid mode")

    def delFile(self, file_name: str | None = None):
        if file_name is None:
            file_name = input("Enter file name: ").strip()
            if file_name == "":
                raise ValueError("File name empty")

        file_name_bytes = file_name.encode()
        signature = create_signature(self._rsa.private_key, (file_name_bytes,))
        file_name_encrypted = encrypedByAES(self._aes_key, file_name_bytes)

        send_data = (
            b"DEL"
            + get_format_bytes_from_message(signature)
            + get_format_bytes_from_message(file_name_encrypted)
        )

        self._sock.sendall(send_data)
        return self.reciveResonse()

    def getFile(self, direcory_path: Path | None = None):
        if direcory_path is None:
            direcory_path = Path(str(input("Enter file path you want to download to: ")).strip())

        file_name = direcory_path.name.encode()
        file_name_encrypted = encrypedByAES(self._aes_key, file_name)
        signature = create_signature(self._rsa.private_key, (file_name,))

        self._sock.sendall(
            b"GET"
            + get_format_bytes_from_message(signature)
            + get_format_bytes_from_message(file_name_encrypted)
        )

        code, body = self.reciveResonse()
        if not body["success"]:
            return code, body

        signature = receive_signature(self._sock, self._rsa.private_key)
        file_name_length = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        file_name = decrypedByAES(self._aes_key, recv_raw_bytes(self._sock, file_name_length)).decode()
        logger.info("File name received: %s", file_name)

        file_size_length = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        file_size = decrypedByAES(self._aes_key, recv_raw_bytes(self._sock, file_size_length)).decode()
        logger.info("File size received: %s", file_size)

        recvStreamingToFileAndVerify(self._sock, self._aes_key, direcory_path, signature)
        return self.reciveResonse()

    def sendData(self, file_path: Path | None = None):
        if file_path is None:
            raw_path = str(input("Enter file path: ")).strip()
            if raw_path == "":
                raise ValueError("File path is empty")
            file_path = Path(raw_path)
            if not file_path.exists():
                raise FileNotFoundError("File does not exist")

        file_name = file_path.name
        file_size = file_path.stat().st_size

        salt = HashingSHA_256.generate_salt()
        file_data_hash = HashingSHA_256.hashingFile(file_path, salt)
        signature = RSA.encrypt_bytes_with_key(file_data_hash, self._rsa.private_key)

        metadata = get_format_bytes_from_message(file_name) + file_size.to_bytes(4, "big")
        metadata_encrypted = encrypedByAES(self._aes_key, metadata)

        self._sock.sendall(
            b"PST"
            + get_format_bytes_from_message(signature)
            + get_format_bytes_from_message(metadata_encrypted)
        )

        startStream(self._aes_key, self._sock, file_path)
        return self.reciveResonse()

    def listData(self):
        self._sock.sendall(b"LIS")

        code, body = self.reciveResonse()
        if not body["success"]:
            return code, body
        
        signature = receive_signature(self._sock, self._rsa.private_key)

        tuple_length = int.from_bytes(recv_raw_bytes(self._sock, 4), "big")
        encrypted_names = recv_raw_bytes(self._sock, tuple_length)
        if not HashingSHA_256.verifyHash(encrypted_names, signature):
            raise ValueError("Received names list does not pass signature verification")
        names_tuple = literal_eval(decrypedByAES(self._aes_key, encrypted_names).decode())

        return code, body, names_tuple


def main() -> None:
    client = Client()

    try:
        if not client.connect():
            raise ConnectionError("Failed to connect to server")
        client.AUTorREG()
        client.startComLoop()
    except Exception:
        logger.exception("Client error")
    finally:
        client.close_connection()


if __name__ == "__main__":
    main()
