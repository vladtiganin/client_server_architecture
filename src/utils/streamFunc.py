from src.utils.AESfuncs import decrypedByAES
from src.utils.bytesFuncs import recvRawBytes, getFromatBytesFromMess
from src.utils.AESfuncs import decrypedByAES, encrypedByAES
from src.utils.createLogger import createLogger
import logging
from pathlib import Path
from src.utils.DBMenager import DBMenager
import apsw


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


def startStream(aes_key, sock ,path: Path) -> None:
        MB = 1024 * 1024

        try:
            with open(path, "rb") as file:
                   while True:
                        chunck = file.read(MB)
                        if not chunck:
                           break
                        logger.debug(f"Chanck lenth {len(chunck)}")
                        chunck_enc = encrypedByAES(aes_key, chunck)
                        sock.sendall(getFromatBytesFromMess(chunck_enc))
        except Exception as ex:
            logger.exception("Error during streamig : ")

        sock.sendall((0).to_bytes(4, 'big'))
        logger.info("Streaming ends") 

