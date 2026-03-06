# from ..clientHandler import ClientHandler
from src.utils.bytesFuncs import recvRawBytes
from src.utils.AESfuncs import decrypedByAES
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def handleAUT(handler):
    signature = handler.recive_signature()
    logger.debug(f"Client AUT signature: {signature}")

    login, password = recvLP(handler)

    if not HashingSHA_256.verifyHash(login + password, signature): raise ValueError
    else : logger.debug("Data verifeideo")



def  recvLP(handler) -> tuple[bytes]:
    data_lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')

    LPencr = recvRawBytes(handler.conn, data_lenth)
    LPdecrpt = decrypedByAES(handler.aes_key, LPencr)

    login_lenth = int.from_bytes(LPdecrpt[:4], 'big')
    login = LPdecrpt[4: 4 + login_lenth]

    password_lenth = int.from_bytes(LPdecrpt[4 + login_lenth : 4 + login_lenth + 4], 'big')
    password = LPdecrpt[4 + login_lenth + 4 : 4 + login_lenth + 4 + password_lenth]

    # login_lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')
    # login = recvRawBytes(handler.conn, login_lenth)

    # password_lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')
    # password = recvRawBytes(handler.conn, password_lenth)

    return login, password