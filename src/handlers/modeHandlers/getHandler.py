from src.utils.bytesFuncs import recvRawBytes, createSignature, getFromatBytesFromMess, reciveSignature
from src.utils.hashing import HashingSHA_256
import logging
from src.utils.createLogger import createLogger
from src.handlers.modeHandlers.recv import recvLP
from src.utils.DBManager import DBManager
from src.utils.AESfuncs import decrypedByAES, encrypedByAES
from src.handlers.modeHandlers.lisHandler import extractNamesList
from src.utils.streamFunc import startStream
from src.utils.responseFuncs import sendResponse
import hashlib
from src.utils.RSA.rsa_core import RSA


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)


def handleGET(handler):
    signature = reciveSignature(handler.conn, handler._client_pubk)
    logger.info("Recive signature")

    lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')
    file_name = decrypedByAES(handler.aes_key, recvRawBytes(handler.conn, lenth)).decode()
    logger.info("Recive file name")
    logger.debug(f"File name : {file_name}")

    names_tuple = extractNamesList(handler)
    logger.debug(f"Names tuple : {names_tuple}")

    if file_name not in names_tuple: 
        sendResponse(handler, 200, False, "File not found")
        print("File does not exists")
        return
    else:
        sendResponse(handler, 200, True, "File exists, start streaming")

    
    db = DBManager("bd.sqlite")
    params = db.execute('''
        SELECT id, name, size FROM Files WHERE name = ? 
    ''', (file_name, ))[0] 
    logger.debug(f"File params : {params}") #id, name, size

    data_hash = HashingSHA_256.hashBLOB(
        table_name="Files",
        column_name="data",
        row_id=params[0]
    )
    logger.info("BLOB successfully hashed")

    signature = RSA.encrypt_bytes_with_key(data_hash, handler._client_pubk)
    logger.info("Signature created")

    name_encr = encrypedByAES(handler.aes_key, params[1].encode())
    logger.debug("Name encrypted")
    size_encr = encrypedByAES(handler.aes_key, params[2].encode())
    logger.debug("Size encrypted")

    meta_data = (getFromatBytesFromMess(signature) +
                 getFromatBytesFromMess(name_encr) +
                 getFromatBytesFromMess(size_encr))
    logger.info("Meta data created")

    handler.conn.sendall(meta_data)
    logger.info("Meta data sent")


    try:
        for chunk in db.readBLOB("Files", "data", params[0]):
            chunk = encrypedByAES(handler.aes_key, chunk)
            handler.conn.sendall(getFromatBytesFromMess(chunk))
            logger.debug(f"Chunk lenth {len(chunk)}")
    except Exception as ex:
        logger.exception()
    finally:
        handler.conn.sendall((0).to_bytes(4, 'big'))
        logger.debug(f"Chunk lenth {len(chunk)}")

    
    sendResponse(handler, 200, True, "Data sent")
    
    logger.info("All data sent")