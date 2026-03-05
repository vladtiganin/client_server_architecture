from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
import os

def encrypedByAES(aes_key , data: bytes) -> bytes:
    nonce = get_random_bytes(8)
    cipher_encrypt = AES.new(
        key=aes_key,
        mode=AES.MODE_CTR,
        nonce=nonce
    )

    cipher_text = cipher_encrypt.encrypt(data)
    return nonce + cipher_text


def decrypedByAES(aes_key, cipher_data: bytes) -> bytes:
    nonce = cipher_data[:8]
    cipher_text = cipher_data[8:]

    cipher_decrypt = AES.new(
        key=aes_key,
        mode=AES.MODE_CTR,
        nonce=nonce
    )

    return cipher_decrypt.decrypt(cipher_text)