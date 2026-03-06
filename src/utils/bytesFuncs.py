from src.utils import createLogger
import logging
from src.utils.RSA.rsa_core import RSAKey

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def bigIntToBytes(number: int, bytes_order = "big") -> bytes:
    logger.debug(f"Input number {number}")
    if number == 0: return b'\x00'

    byte_lenth = (number.bit_length() + 7) // 8
    logger.debug(f"Bytes lenth {byte_lenth}")
    return number.to_bytes(byte_lenth, byteorder=bytes_order)


def bytesToBigInt(bytes_data: bytes, bytes_order = "big") -> int:
    logger.debug(f"Bytes lenth {len(bytes_data)}")
    return int.from_bytes(bytes_data, byteorder=bytes_order)


def recvRawBytes(sock, lenth: int) -> bytes | None:
    data = b""
    while(len(data) < lenth):
        pock = sock.recv(lenth - len(data))
        # if not pock: return None
        data += pock
    return data


def getFromatBytesFromMess(message: str | int) -> bytes:
    if isinstance(message, int): return bigIntToBytes(message)
    
    msg_enc = message.encode()
    lenth = len(msg_enc)
    return lenth.to_bytes(4, byteorder='big') + msg_enc


def getFormatBytesFromRSAKey(key : RSAKey) -> bytes:
    key_part_1_enc = bigIntToBytes(key.first)
    key_part_2_enc = bigIntToBytes(key.second)
    lenth_1, lenth_2 = len(key_part_1_enc), len(key_part_2_enc)
    logger.debug(f"lenth_1: {lenth_1}")
    logger.debug(f"lenth_2: {lenth_2}")

    return (lenth_1.to_bytes(4,byteorder='big') + 
            lenth_2.to_bytes(4,byteorder='big') + 
            key_part_1_enc + 
            key_part_2_enc)

def getRSAKeyFromBytes(sock) -> RSAKey:
    lenth_1 = int.from_bytes(
        bytes=recvRawBytes(sock, 4),
        byteorder='big')
    lenth_2 = int.from_bytes(
        bytes=recvRawBytes(sock, 4),
        byteorder='big')
    
    key_part_1 = bytesToBigInt(
        bytes_data=recvRawBytes(
                sock=sock,
                lenth=lenth_1),
        bytes_order='big')
    key_part_2 = bytesToBigInt(
        bytes_data=recvRawBytes(
                sock=sock,
                lenth=lenth_2),
        bytes_order='big')
    
    return RSAKey(key_part_1, key_part_2)

