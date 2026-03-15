import logging
from src.utils.createLogger import createLogger
from src.utils.AESfuncs import decrypedByAES, encrypedByAES


logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def sendResponse(handler, code:int, success: bool, message: str):
    response_body = {
        "success" : success,
        "message" : message
    } 

    logger.debug(f"Response data : {response_body}")

    response_body_encr = encrypedByAES(handler.aes_key, repr(response_body).encode())

    from src.utils.bytesFuncs import getFromatBytesFromMess
    handler.conn.sendall(code.to_bytes(4, 'big') +
                        getFromatBytesFromMess(response_body_encr)) 