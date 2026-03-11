# from ..clientHandler import ClientHandler
from src.utils.bytesFuncs import recvRawBytes, createSignature, getFromatBytesFromMess
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.handlers.modeHandlers.recv import recvLP
from src.utils.DBManager import DBManager
from src.utils.AESfuncs import decrypedByAES, encrypedByAES


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def handleLIS(handler):
    data_tuple = extractNamesList(handler)

    data_tuple_bytes = encrypedByAES(handler.aes_key, repr(data_tuple).encode())
    logger.debug(f"fata tuple bytes : {data_tuple_bytes}")

    signature = createSignature(handler._client_pubk, (data_tuple_bytes, ))

    send_data = (getFromatBytesFromMess(signature) + 
                 getFromatBytesFromMess(data_tuple_bytes))

    try:
        handler.conn.sendall(send_data)
    except Exception as ex:
        logger.exception("Error during sending tuple of names : ")

def extractNamesList(handler):
    bd = DBManager("bd.sqlite")
    data_list_tmp = bd.execute('''
    SELECT name FROM Files WHERE user_id = (
        SELECT id FROM Users WHERE login = ?  
        )
    ''', (handler.client_login, ))
    logger.info("Data list extracted")
    logger.debug(f"Data list raw: {data_list_tmp}")

    data_tuple = list(i[0] for i in data_list_tmp)
    logger.debug(f"Data list formated: {data_tuple}")

    return data_tuple


