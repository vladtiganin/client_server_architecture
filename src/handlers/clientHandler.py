import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSAKey
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getRSAKeyFromBytes, recvRawBytes
import json
from src.utils.hashing import HashingSHA_256

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

def clientHandler(conn):
    logger.debug("Start handle client")
    
    pk = getRSAKeyFromBytes(conn)
    logger.debug(pk.first)
    logger.debug(pk.second)


    json_lenth = int.from_bytes(recvRawBytes(conn, 4), 'big')
    logger.debug(f"Signature lenth : {json_lenth}")
    dict_hash_data = json.loads(recvRawBytes(conn, json_lenth).decode('utf-8'))

    sig_lenth = int.from_bytes(recvRawBytes(conn, 4), 'big')
    signature = recvRawBytes(conn, sig_lenth)
    signature = RSA.decrypt_bytes_with_key(signature, pk)


    logger.debug(f"signature : {signature}")

    # signature = json.loads(signature.decode('utf-8'))
    logger.debug("Load signature")
    # lenth = int.from_bytes(recvRawBytes(conn, 4), 'big')




    
    # if(HashingSHA_256.verifyHash(pk, signature)) : print("good")
    # else : print("No") 