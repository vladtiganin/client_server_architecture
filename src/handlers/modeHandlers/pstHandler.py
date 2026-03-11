from src.handlers.modeHandlers.recv import recvMetaData
from src.utils.streamFunc import recvStreaming
from src.utils.bytesFuncs import recvRawBytes, reciveSignature
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.utils.DBManager import DBManager

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

db = DBManager("bd.sqlite")
logger.info("Create DBMenager")


def handlePST(handler):
    signature = reciveSignature(handler.conn, handler._client_pubk)
    logger.debug(f"Client PST signature: {signature}")

    meta_data = recvMetaData(handler.conn, handler.aes_key)
    logger.debug(f"recv mets data : {meta_data}")

    # recved_data = recvStreaming(handler.conn, handler.aes_key)
    # logger.debug(f"recved_data: {recved_data}")


    result = db.writeAndHashBLOB(*meta_data, handler, signature)

    if result : logger.info("All good blob write")
    else: logger.warning("Data does not matches with signature")

    # logger.debug(f"Try to verify:")
    # if not HashingSHA_256.verifyHash(recved_data, signature) : 
    #     raise ValueError("Recived data does not match with signature")
    
    # addToDataBase(handler.client_login, *meta_data, recved_data)


def addToDataBase(login: str, file_name: str, file_size: int, data:bytes):

    logger.debug(f"Users login : {login}")
    user_id = db.execute('''
        SELECT id from Users WHERE login = ?
    ''', (login.strip(),))[0][0]
    logger.info(f"Users id {user_id}")

    db.execute('''
        INSERT INTO Files (name, size, ZEROBLOB(?), user_id)
        VALUES (?,?,?,?) 
    ''', (file_name, str(file_size), file_size, user_id))


# def addToDataBase(login: str, file_name: str, file_size: int, data:bytes):
#     db = DBMenager("bd.sqlite")
#     logger.info("Create DBMenager")

#     logger.debug(f"Users login : {login}")
#     user_id = db.execute('''
#         SELECT id from Users WHERE login = ?
#     ''', (login.strip(),))[0][0]
#     logger.info(f"Users id {user_id}")

#     db.execute('''
#         INSERT INTO Files (name, size, data, user_id)
#         VALUES (?,?,?,?) 
#     ''', (file_name, str(file_size), data, user_id))




    