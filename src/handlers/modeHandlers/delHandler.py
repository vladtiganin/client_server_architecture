from src.handlers.modeHandlers.recv import recvMetaData
from src.utils.streamFunc import recvStreaming
from src.utils.bytesFuncs import recvRawBytes, reciveSignature
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.utils.DBManager import DBManager
from src.utils.AESfuncs import decrypedByAES
from src.utils.responseFuncs import sendResponse
from src.handlers.modeHandlers.lisHandler import extractNamesList

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def handleDEL(handler):
    signature = reciveSignature(handler.conn, handler._client_pubk)
    logger.debug("Signature recived")

    data_lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')
    data = decrypedByAES(handler.aes_key, recvRawBytes(handler.conn, data_lenth)).decode()
    logger.debug(f"Data recived : {data}")

    if not HashingSHA_256.verifyHash(data.encode(), signature):
        sendResponse(handler, 400, False, "Data broken")
        return

    names = extractNamesList(handler)
    if data not in list([i[0] for i in names]):
        sendResponse(handler, 200, False, "File not found")
        return

    db = DBManager("bd.sqlite")
    user_id = db.execute('''
        SELECT id FROM Users WHERE login = ?
    ''', (handler.client_login, ))[0][0]
    logger.debug(f"Extracted user id : {user_id}")

    db.execute('''
        DELETE FROM Files
        WHERE name = ? AND user_id = ? 
    ''',(data, user_id))
    logger.info("File deleted")

    sendResponse(handler, 200, True, "File deleted")



