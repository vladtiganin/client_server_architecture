from src.utils.AESfuncs import decrypedByAES
from src.utils.bytesFuncs import recvRawBytes
from src.utils.AESfuncs import decrypedByAES
from src.utils.createLogger import createLogger
import logging


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def  recvLP(handler) -> tuple[bytes]:
    data_lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')

    LPencr = recvRawBytes(handler.conn, data_lenth)
    LPdecrpt = decrypedByAES(handler.aes_key, LPencr)

    login_lenth = int.from_bytes(LPdecrpt[:4], 'big')
    login = LPdecrpt[4: 4 + login_lenth]

    password_lenth = int.from_bytes(LPdecrpt[4 + login_lenth : 4 + login_lenth + 4], 'big')
    password = LPdecrpt[4 + login_lenth + 4 : 4 + login_lenth + 4 + password_lenth]

    return login, password


def recvMetaData(conn, aes_key) -> tuple[str,int]:
    lenth = int.from_bytes(recvRawBytes(conn, 4), "big")
    meta_data = decrypedByAES(aes_key, recvRawBytes(conn, lenth))
    logger.debug(f"Meta data lenth : {lenth}")
    logger.debug(f"Meta data : {meta_data}")

    file_name_lenth = int.from_bytes(meta_data[:4], 'big')
    logger.debug(f"File name lenth : {file_name_lenth}")
    file_name = meta_data[4: 4 + file_name_lenth].decode()
    logger.debug(f"File name  : {file_name}")

    file_size = int.from_bytes(meta_data[4 + file_name_lenth: 4 + file_name_lenth + 4], 'big')
    logger.debug(f"File size : {file_size}")

    return (file_name, file_size)