import socket
import logging
from src.utils import createLogger
from src.utils.RSA.rsa_core import RSA
from src.utils.bytesFuncs import getFormatBytesFromRSAKey, bigIntToBytes
from src.utils.hashing import HashingSHA_256
import json


logger = createLogger("client")
logger.setLevel(logging.DEBUG)


def main():
    logger.debug("Start working...")

    try:
        sock = socket.socket()
        sock.connect(("localhost", 9090))
    except Exception as ex:
        logger.exception("Error during connecting to server: ")

    rsa = RSA()
    rsa.generate_keys(1024)


    public_key_bytes = getFormatBytesFromRSAKey(rsa.public_key)
    public_key_bytes_hash = HashingSHA_256.hashingBytes(public_key_bytes)
    hash_bytes = bytes.fromhex(json.loads(public_key_bytes_hash.decode('utf-8'))['hash_data'])
    client_signature = RSA.encrypt_bytes_with_key(hash_bytes, rsa.private_key)
    

    send_data = (public_key_bytes +
                 len(public_key_bytes_hash).to_bytes(4,'big')+
                 public_key_bytes_hash +
                 len(client_signature).to_bytes(4,'big')+
                 client_signature)
    
    logger.debug(f"Signature lenth : {len(client_signature)}")

    try:
        sock.sendall(send_data)
    except Exception as ex:
        logger.exception("Error during sending key: ")



    logger.debug(rsa.public_key.first)
    logger.debug(rsa.public_key.second)

    # user_str = input("Enter: ")
    # sock.send(user_str.encode())
    # data = sock.recv(1024)

    # print(data.decode())

    sock.close()
    logger.debug("End working...")



if __name__ == "__main__":
    main()