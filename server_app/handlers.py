from __future__ import annotations

import logging
import socket
import sqlite3

from Crypto.Random import get_random_bytes


from server_app.RSA import RSA
from server_app.crypto import (
    HashingSHA_256,
    create_logger,
    create_signature,
    decrypedByAES,
    encrypedByAES,
    get_format_bytes_from_message,
    get_rsa_key_from_bytes,
    receive_signature,
    recv_raw_bytes,
)
from server_app.db import DBManager

logger = create_logger(__name__)
logger.setLevel(logging.DEBUG)


def send_response(handler, code: int, success: bool, message: str) -> None:
    response_body = {"success": success, "message": message}
    response_body_encrypted = encrypedByAES(handler.aes_key, repr(response_body).encode())
    handler.conn.sendall(code.to_bytes(4, "big") + get_format_bytes_from_message(response_body_encrypted))


def unsureAuthorized(handler) -> bool:
    if handler.client_login is None:
        send_response(handler, 200, False, "User not authorized")
        return False
    return True


def recv_lp(handler) -> tuple[bytes, bytes]:
    data_length = int.from_bytes(recv_raw_bytes(handler.conn, 4), "big")
    lp_encrypted = recv_raw_bytes(handler.conn, data_length)
    lp_decrypted = decrypedByAES(handler.aes_key, lp_encrypted)

    login_length = int.from_bytes(lp_decrypted[:4], "big")
    login = lp_decrypted[4 : 4 + login_length]

    password_length = int.from_bytes(lp_decrypted[4 + login_length : 8 + login_length], "big")
    password = lp_decrypted[8 + login_length : 8 + login_length + password_length]

    return login, password


def recv_metadata(conn, aes_key) -> tuple[str, int]:
    length = int.from_bytes(recv_raw_bytes(conn, 4), "big")
    metadata = decrypedByAES(aes_key, recv_raw_bytes(conn, length))

    file_name_length = int.from_bytes(metadata[:4], "big")
    file_name = metadata[4 : 4 + file_name_length].decode()
    file_size = int.from_bytes(metadata[4 + file_name_length : 8 + file_name_length], "big")

    return file_name, file_size


def iter_plain_chunks(conn, aes_key):
    while True:
        length = recv_raw_bytes(conn, 4)
        if not length or length == b"\x00\x00\x00\x00":
            break
        yield decrypedByAES(aes_key, recv_raw_bytes(conn, int.from_bytes(length, "big")))


class ClientHandler:
    def __init__(self, conn: socket.socket):
        if conn is None:
            raise ValueError("Empty socket")

        self.client_login = None
        self.conn = conn
        self._client_pubk = None
        self.aes_key = None

    def handshake(self):
        self._client_pubk = get_rsa_key_from_bytes(self.conn)
        client_signature_bytes = receive_signature(self.conn, self._client_pubk)

        if not HashingSHA_256.verifyHashRSAKey(self._client_pubk, client_signature_bytes):
            raise ValueError("Received RSA key data was modified")

        self.aes_key = get_random_bytes(32)
        data_to_send = self.__generate_aes_exchange_message()
        self.conn.sendall(data_to_send)

    def __generate_aes_exchange_message(self) -> bytes:
        aes_key_hash = HashingSHA_256.hashingBytes(self.aes_key)
        server_signature_bytes = RSA.encrypt_bytes_with_key(aes_key_hash, self._client_pubk)
        encrypted_aes_bytes = RSA.encrypt_bytes_with_key(self.aes_key, self._client_pubk)

        return (
            len(encrypted_aes_bytes).to_bytes(4, "big")
            + encrypted_aes_bytes
            + len(server_signature_bytes).to_bytes(4, "big")
            + server_signature_bytes
        )

    def start_communication_loop(self):
        while True:
            mode = recv_raw_bytes(self.conn, 3)
            if not mode:
                logger.info("Client disconnect, out from loop")
                break

            mode = mode.decode()
            logger.info("Mode received: %s", mode)

            match mode:
                case "PST":
                    handle_pst(self)
                case "LIS":
                    handle_lis(self)
                case "GET":
                    handle_get(self)
                case "DEL":
                    handle_del(self)
                case "AUT":
                    self.client_login = handle_aut(self)
                case "REG":
                    self.client_login = handle_reg(self)
                case _:
                    raise ValueError("Invalid mode")


def handle_aut(handler) -> str | None:
    signature = receive_signature(handler.conn, handler._client_pubk)
    login, password = recv_lp(handler)

    if not HashingSHA_256.verifyHash(login + password, signature):
        send_response(handler, 400, False, "Received broken data")
        return None

    db = DBManager()
    user_data = db.get_user(login.decode())
    if user_data is None:
        send_response(handler, 200, False, "Invalid login or password")
        return None

    login_db = user_data[1]
    password_hash_db = user_data[2]
    if not HashingSHA_256.verifyHash(password, password_hash_db):
        send_response(handler, 200, False, "Invalid login or password or broken data")
        return None

    send_response(handler, 200, True, "Authorized")
    return login_db


def handle_reg(handler) -> str | None:
    signature = receive_signature(handler.conn, handler._client_pubk)
    login, password = recv_lp(handler)

    if not HashingSHA_256.verifyHash(login + password, signature):
        send_response(handler, 200, False, "Received broken data")
        return None

    password_hash = HashingSHA_256.hashingBytes(password)
    db = DBManager()

    try:
        insert_result = db.execute(
            """
            INSERT INTO Users (login, password_hash)
            VALUES (?, ?)
            """,
            (login.decode(), password_hash),
        )
    except sqlite3.IntegrityError:
        logger.exception("Insert unique error")
        send_response(handler, 409, False, "Already exists")
        return None

    if insert_result is None:
        send_response(handler, 500, False, "Something goes wrong, try again later")
        return None

    send_response(handler, 200, True, "User registered")
    return login.decode()


def handle_lis(handler) -> None:
    if not unsureAuthorized(handler):
        return

    db = DBManager()
    data_list = db.list_user_files(handler.client_login)
    data_tuple_bytes = encrypedByAES(handler.aes_key, repr(data_list).encode())
    signature = create_signature(handler._client_pubk, (data_tuple_bytes,))
    send_data = get_format_bytes_from_message(signature) + get_format_bytes_from_message(data_tuple_bytes)

    send_response(handler, 200, True, "List sent")
    handler.conn.sendall(send_data)


def handle_del(handler) -> None:
    if not unsureAuthorized(handler):
        return

    signature = receive_signature(handler.conn, handler._client_pubk)
    data_length = int.from_bytes(recv_raw_bytes(handler.conn, 4), "big")
    file_name = decrypedByAES(handler.aes_key, recv_raw_bytes(handler.conn, data_length)).decode()

    if not HashingSHA_256.verifyHash(file_name.encode(), signature):
        send_response(handler, 400, False, "Data broken")
        return

    db = DBManager()
    file_row = db.get_user_file(handler.client_login, file_name)
    if file_row is None:
        send_response(handler, 200, False, "File not found")
        return

    db.delete_user_file(handler.client_login, file_name)
    send_response(handler, 200, True, "File deleted")


def handle_pst(handler) -> None:
    if not unsureAuthorized(handler):
        return

    signature = receive_signature(handler.conn, handler._client_pubk)
    file_name, file_size = recv_metadata(handler.conn, handler.aes_key)

    db = DBManager()
    success, message = db.store_user_file(
        handler.client_login,
        file_name,
        file_size,
        iter_plain_chunks(handler.conn, handler.aes_key),
        signature,
    )
    send_response(handler, 200 if success else 400, success, message)


def handle_get(handler) -> None:
    if not unsureAuthorized(handler):
        return

    signature = receive_signature(handler.conn, handler._client_pubk)
    length = int.from_bytes(recv_raw_bytes(handler.conn, 4), "big")
    file_name = decrypedByAES(handler.aes_key, recv_raw_bytes(handler.conn, length)).decode()

    if not HashingSHA_256.verifyHash(file_name.encode(), signature):
        send_response(handler, 400, False, "Data broken")
        return

    db = DBManager()
    params = db.get_user_file(handler.client_login, file_name)
    if params is None:
        send_response(handler, 200, False, "File not found")
        return

    send_response(handler, 200, True, "File exists, start streaming")

    data_hash = db.hash_blob(params[0])
    blob_signature = RSA.encrypt_bytes_with_key(data_hash, handler._client_pubk)
    name_encrypted = encrypedByAES(handler.aes_key, params[1].encode())
    size_encrypted = encrypedByAES(handler.aes_key, str(params[2]).encode())

    metadata = (
        get_format_bytes_from_message(blob_signature)
        + get_format_bytes_from_message(name_encrypted)
        + get_format_bytes_from_message(size_encrypted)
    )
    handler.conn.sendall(metadata)

    for chunk in db.iter_blob_chunks(params[0]):
        chunk_encrypted = encrypedByAES(handler.aes_key, chunk)
        handler.conn.sendall(get_format_bytes_from_message(chunk_encrypted))

    handler.conn.sendall((0).to_bytes(4, "big"))
    send_response(handler, 200, True, "Data sent")


def clientHandler(conn):
    logger.debug("Start handle client")

    handler = ClientHandler(conn)
    try:
        handler.handshake()
        handler.start_communication_loop()
    except Exception:
        logger.exception("Error")
        if handler.aes_key is not None:
            send_response(handler, 500, False, "Something goes wrong")
    finally:
        try:
            handler.conn.close()
        except Exception:
            logger.exception("Error during connection close")

    logger.debug("End handle client")