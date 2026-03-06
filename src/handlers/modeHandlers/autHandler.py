# from ..clientHandler import ClientHandler
from src.utils.bytesFuncs import recvRawBytes
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.handlers.modeHandlers.recvLP import recvLP
from src.utils.DBMenager import DBMenager


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def handleAUT(handler):
    signature = handler.recive_signature()
    logger.debug(f"Client AUT signature: {signature}")

    login, password = recvLP(handler)
    logger.debug(f"Recived login : {login}")
    logger.debug(f"Recived password : {password}")

    if not HashingSHA_256.verifyHash(login + password, signature): raise ValueError
    else : logger.debug("Data verifeideo")

    db = DBMenager("bd.sqlite")
    logger.debug(f"DB created")

    user_data = db.execute('''
        SELECT * FROM Users
        WHERE login = ?
    ''', (login.decode(), ))
    logger.debug(f"User_data lenth: {len(user_data)}")
    logger.debug(f"{user_data}")

    login_db = user_data[0][1]
    logger.debug(f"login : {login_db}")

    pass_hash_db = user_data[0][2]
    logger.debug(f"password_hash : {pass_hash_db}")

    if HashingSHA_256.verifyHash(password, pass_hash_db) : print("good")
    else : print("no")

