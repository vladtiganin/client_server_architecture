import logging
from src.utils.createLogger import createLogger
import hashlib
import os
import json
import base64

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

class HashingSHA_256:

    @staticmethod
    def generate_salt(lenth = 32):
        return os.urandom(32)
        logger.debug("Salt generated")
    
    @staticmethod
    def hashingBytes(data_bytes:bytes, salt = None) -> bytes:
        if salt is None:
            logger.debug("Salt is None, generate new one")
            salt = HashingSHA_256.generate_salt(32)

        salted_data = salt + data_bytes  
        hash_data = hashlib.sha256(salted_data).digest()

        return_dict = {
            "salt" : salt.hex(),
            "hash_data" : hash_data.hex()
        }


        return_dict_bytes = (json.dumps(return_dict)).encode('utf-8')
        logger.debug(f"return_dict_bytes : {return_dict_bytes}")

        return return_dict_bytes
    

    @staticmethod
    def verifyHash(data_to_verify,data_bytes: bytes) -> bool:
        salt = bytes.fromhex(data_bytes[:32])
        hash_data = bytes.fromhex(data_bytes[32:])

        new_hash_data = hashlib.sha256(salt + data_to_verify) 
        if(new_hash_data == hash_data) : return True
        else : return False

