from src.utils import createLogger
import logging

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