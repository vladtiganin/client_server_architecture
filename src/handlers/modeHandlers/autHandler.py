# from ..clientHandler import ClientHandler
from src.utils.bytesFuncs import recvRawBytes, reciveSignature, getFromatBytesFromMess
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.responseFuncs import sendResponse
from src.utils.createLogger import createLogger
from src.handlers.modeHandlers.recv import recvLP
from src.utils.DBManager import DBManager
from src.utils.AESfuncs import encrypedByAES


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def handleAUT(handler) -> str:
    signature = reciveSignature(handler.conn, handler._client_pubk)
    logger.debug(f"Client AUT signature: {signature}")

    login, password = recvLP(handler)
    logger.debug(f"Recived login : {login}")
    logger.debug(f"Recived password : {password}")

    if not HashingSHA_256.verifyHash(login + password, signature): raise ValueError
    else : logger.debug("Data verifeide")

    db = DBManager("bd.sqlite")
    logger.debug(f"DB created")

    user_data = db.execute('''
        SELECT * FROM Users
        WHERE login = ?
    ''', (login.decode(), ))
    logger.debug(f"User_data lenth: {len(user_data)}")
    logger.debug(f"{user_data}")

    if len(user_data) == 0:
        sendResponse(handler, 200, False, "Invalid login or password")
        return
        # raise ValueError("The user was not found : incorrect login")

    login_db = user_data[0][1]
    logger.debug(f"login : {login_db}")

    pass_hash_db = user_data[0][2]
    logger.debug(f"password_hash : {pass_hash_db}")

    if not HashingSHA_256.verifyHash(password, pass_hash_db) :
        logger.error("Incorrect password")
        sendResponse(handler, 200, False, "Invalid login or password or broken data")
        return None
    else:
        logger.info("Pasaword correct, user authorized")
        sendResponse(handler, 200, True, "Authorized")

    return login_db
 
