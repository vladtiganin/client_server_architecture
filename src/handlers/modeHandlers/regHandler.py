from src.utils.bytesFuncs import recvRawBytes
from src.utils.AESfuncs import decrypedByAES
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.handlers.modeHandlers.recvLP import recvLP
from src.utils.hashing import HashingSHA_256
from src.utils.DBMenager import DBMenager



logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def handleREG(handler):
    signature = handler.recive_signature()
    logger.debug(f"Client AUT signature: {signature}")

    login, password = recvLP(handler)
    logger.debug(f"Client login: {login}")
    logger.debug(f"Client password: {password}")

    password_hash = HashingSHA_256.hashingBytes(password)
    logger.debug(f"Create hash")

    db = DBMenager("bd.sqlite")
    logger.debug(f"DB created")

    insesrt_result = db.execute('''
        INSERT INTO Users (login, password_hash)
        VALUES(?, ?)
    ''', (login.decode(), password_hash))
    logger.debug(f"INSERT result : {insesrt_result}")    