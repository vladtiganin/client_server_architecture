import logging
from src.utils.createLogger import createLogger
from src.utils.bytesFuncs import getFormatBytesFromRSAKey
import hashlib
import os


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

        return salt + hash_data
    

    @staticmethod
    def verifyHashRSAKey(key_bytes, signature: bytes) -> bool:
        # salt = bytes.fromhex(signature[:32])
        # hash_data = bytes.fromhex(signature[32:])

        salt = (signature[:32])
        hash_data = (signature[32:])

        new_hash_data = hashlib.sha256(salt + getFormatBytesFromRSAKey(key_bytes)).digest() 

        logger.debug(f"Original hash: {hash_data.hex()}")
        logger.debug(f"Calculated hash: {new_hash_data.hex()}")

        if(new_hash_data == hash_data) : return True
        else : return False

    
    def verifyHash(plain_data, signature: bytes) -> bool:
        salt = (signature[:32])
        hash_data = (signature[32:])

        new_hash_data = hashlib.sha256(salt + plain_data).digest() 

        logger.debug(f"Original hash: {hash_data.hex()}")
        logger.debug(f"Calculated hash: {new_hash_data.hex()}")

        return new_hash_data == hash_data

