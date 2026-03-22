from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from client_app.RSA import RSA, RSAKey
from client_app.config import LOG_DIR


def create_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = name.replace("\\", ".").replace("/", ".").replace(":", "_")
    handler = logging.FileHandler(LOG_DIR / f"{safe_name}.log", "w", encoding="utf-8")
    formatter = logging.Formatter("%(name)s %(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


logger = create_logger(__name__)
logger.setLevel(logging.DEBUG)


class HashingSHA_256:
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        return os.urandom(length)

    @staticmethod
    def hashingBytes(data_bytes: bytes, salt: bytes | None = None) -> bytes:
        if salt is None:
            salt = HashingSHA_256.generate_salt()

        return salt + hashlib.sha256(salt + data_bytes).digest()

    @staticmethod
    def hashingFile(file_path: Path, salt: bytes | None = None) -> bytes:
        if salt is None:
            salt = HashingSHA_256.generate_salt()

        sha256 = hashlib.sha256()
        sha256.update(salt)

        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(64 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)

        return salt + sha256.digest()

    @staticmethod
    def verifyHashRSAKey(key_bytes: RSAKey, signature: bytes) -> bool:
        salt = signature[:32]
        hash_data = signature[32:]
        new_hash_data = hashlib.sha256(salt + get_format_bytes_from_rsa_key(key_bytes)).digest()
        return new_hash_data == hash_data

    @staticmethod
    def verifyHash(plain_data: bytes, signature: bytes) -> bool:
        salt = signature[:32]
        hash_data = signature[32:]
        new_hash_data = hashlib.sha256(salt + plain_data).digest()
        return new_hash_data == hash_data


def encrypedByAES(aes_key: bytes, data: bytes) -> bytes:
    nonce = get_random_bytes(8)
    cipher_encrypt = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=nonce)
    return nonce + cipher_encrypt.encrypt(data)


def decrypedByAES(aes_key: bytes, cipher_data: bytes) -> bytes:
    nonce = cipher_data[:8]
    cipher_text = cipher_data[8:]
    cipher_decrypt = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=nonce)
    return cipher_decrypt.decrypt(cipher_text)


def big_int_to_bytes(number: int, bytes_order: str = "big") -> bytes:
    if number == 0:
        return b"\x00"

    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder=bytes_order)


def bytes_to_big_int(bytes_data: bytes, bytes_order: str = "big") -> int:
    return int.from_bytes(bytes_data, byteorder=bytes_order)


def recv_raw_bytes(sock, length: int) -> bytes:
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            if data:
                raise ConnectionError("Incomplete data received from socket")
            return b""
        data += packet
    return data


def get_format_bytes_from_message(message: str | bytes | int) -> bytes:
    if isinstance(message, int):
        return big_int_to_bytes(message)

    if isinstance(message, bytes):
        return len(message).to_bytes(4, byteorder="big") + message

    message_encoded = message.encode()
    return len(message_encoded).to_bytes(4, byteorder="big") + message_encoded


def get_format_bytes_from_rsa_key(key: RSAKey) -> bytes:
    key_part_1_encoded = big_int_to_bytes(key.first)
    key_part_2_encoded = big_int_to_bytes(key.second)

    return (
        len(key_part_1_encoded).to_bytes(4, byteorder="big")
        + len(key_part_2_encoded).to_bytes(4, byteorder="big")
        + key_part_1_encoded
        + key_part_2_encoded
    )


def create_signature(key, data: tuple[bytes, ...]) -> bytes:
    data_bytes = b"".join(data)
    data_hash = HashingSHA_256.hashingBytes(data_bytes)
    return RSA.encrypt_bytes_with_key(data_hash, key)


def receive_signature(conn, key) -> bytes:
    signature_length = int.from_bytes(recv_raw_bytes(conn, 4), "big")
    signature = recv_raw_bytes(conn, signature_length)
    return RSA.decrypt_bytes_with_key(signature, key)


TEXT_EXTENSIONS = {
    ".txt",
    ".text",
    ".md",
    ".markdown",
    ".rst",
    ".rtf",
    ".py",
    ".pyw",
    ".js",
    ".mjs",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".sass",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bash",
    ".zsh",
    ".bat",
    ".cmd",
    ".ps1",
    ".sql",
    ".r",
    ".pl",
    ".php",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".swift",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cs",
    ".lua",
    ".csv",
    ".tsv",
    ".log",
    ".diff",
    ".patch",
    ".svg",
    ".tex",
    ".bib",
    ".nfo",
}


def recvStreamingToFileAndVerify(conn, aes_key: bytes, path: Path, signature: bytes) -> bool:
    sha = hashlib.sha256()
    salt = signature[:32]
    sha.update(salt)

    path.parent.mkdir(parents=True, exist_ok=True)
    text_mode = path.suffix.lower() in TEXT_EXTENSIONS
    mode = "w" if text_mode else "wb"
    kwargs = {"encoding": "utf-8"} if text_mode else {}

    with open(path, mode, **kwargs) as file:
        while True:
            length = recv_raw_bytes(conn, 4)
            if not length or length == b"\x00\x00\x00\x00":
                break

            data = decrypedByAES(aes_key, recv_raw_bytes(conn, int.from_bytes(length, "big")))
            if text_mode:
                file.write(data.decode())
            else:
                file.write(data)
            sha.update(data)

    if sha.digest() == signature[32:]:
        return True

    path.unlink(missing_ok=True)
    return False


def startStream(aes_key: bytes, sock, path: Path) -> None:
    chunk_size = 1024 * 1024
    with open(path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            chunk_encrypted = encrypedByAES(aes_key, chunk)
            sock.sendall(get_format_bytes_from_message(chunk_encrypted))

    sock.sendall((0).to_bytes(4, "big"))
