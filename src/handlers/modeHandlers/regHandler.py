from src.utils.bytesFuncs import recvRawBytes, reciveSignature
from src.utils.AESfuncs import decrypedByAES
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.handlers.modeHandlers.recv import recvLP
from src.utils.hashing import HashingSHA_256
from src.utils.DBManager import DBManager
import sqlite3



logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def handleREG(handler) -> str:
    signature = reciveSignature(handler.conn, handler._client_pubk)
    logger.debug(f"Client REG signature: {signature}")

    login, password = recvLP(handler)
    logger.debug(f"Client login: {login}")
    logger.debug(f"Client password: {password}")

    password_hash = HashingSHA_256.hashingBytes(password)
    logger.debug(f"Create hash")

    db = DBManager("bd.sqlite")
    logger.debug(f"DB created")


    insesrt_result = None
    try:
        insesrt_result = db.execute('''
            INSERT INTO Users (login, password_hash)
            VALUES(?, ?)
        ''', (login.decode(), password_hash))
    except sqlite3.IntegrityError as ex:
         logger.exception("Insert unique error: ")
    
    if insesrt_result is None : raise ValueError("REG error")

    logger.debug(f"INSERT result : {insesrt_result}") 

    return  login.decode()
            