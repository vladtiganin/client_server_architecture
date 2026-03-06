from src.utils.AESfuncs import decrypedByAES
from src.utils.bytesFuncs import recvRawBytes

def  recvLP(handler) -> tuple[bytes]:
    data_lenth = int.from_bytes(recvRawBytes(handler.conn, 4), 'big')

    LPencr = recvRawBytes(handler.conn, data_lenth)
    LPdecrpt = decrypedByAES(handler.aes_key, LPencr)

    login_lenth = int.from_bytes(LPdecrpt[:4], 'big')
    login = LPdecrpt[4: 4 + login_lenth]

    password_lenth = int.from_bytes(LPdecrpt[4 + login_lenth : 4 + login_lenth + 4], 'big')
    password = LPdecrpt[4 + login_lenth + 4 : 4 + login_lenth + 4 + password_lenth]

    return login, password