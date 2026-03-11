from src.utils.AESfuncs import decrypedByAES
from src.utils.bytesFuncs import recvRawBytes, getFromatBytesFromMess
from src.utils.AESfuncs import decrypedByAES, encrypedByAES
from src.utils.createLogger import createLogger
import logging
from pathlib import Path
import hashlib

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def recvStreaming(conn, aes_key) -> bytes: 
    recvedData = b""

    while True:
        try:
            lenth = recvRawBytes(conn, 4)
            logger.debug(f"lenth bytes : {lenth}")
            if not lenth or lenth == b'\x00\x00\x00\x00':
                break
            lenth = int.from_bytes(lenth, 'big')
            logger.debug(f"lenth : {lenth}")
            
            data = decrypedByAES(aes_key, recvRawBytes(conn, lenth))
            recvedData += data
            logger.debug(f"recvedData += data = {recvedData}")
        except Exception as ex:
            logger.exception("Error during recive strimming : ")
            break

    logger.info("out from loop")
    return recvedData


def recvStreamingToFileAndVerify(conn, aes_key, path : Path, signature):
    sha = hashlib.sha256()
    salt = signature[:32]
    sha.update(salt)

    with open(path, "a+") as file:

        while True:
            try:
                lenth = recvRawBytes(conn, 4)
                logger.debug(f"lenth bytes : {lenth}")
                if not lenth or lenth == b'\x00\x00\x00\x00':
                    break
                lenth = int.from_bytes(lenth, 'big')
                logger.debug(f"lenth : {lenth}")

                data = decrypedByAES(aes_key, recvRawBytes(conn, lenth))
                file.write(data.decode())
                sha.update(data)

                # recvedData += data
                logger.debug(f"data : {data}")
            except Exception as ex:
                logger.exception("Error during recive strimming : ")
                break

    logger.info("out from loop")

    if sha.digest() == signature[32:]:
        logger.info("Data verified, good")
        return True
    
    logger.info("Data does not match with signature")
    logger.debug("Delete file")

    path.unlink(missing_ok=True)
    return False

    # return recvedData


def startStream(aes_key, sock ,path: Path) -> None:
        MB = 1024 * 1024    
        with open(path, "rb") as file:
               while True:
                    chunck = file.read(MB)
                    if not chunck:
                       break
                    logger.debug(f"Chanck lenth {len(chunck)}")
                    chunck_enc = encrypedByAES(aes_key, chunck)
                    sock.sendall(getFromatBytesFromMess(chunck_enc))


        sock.sendall((0).to_bytes(4, 'big'))
        logger.info("Streaming ends") 

