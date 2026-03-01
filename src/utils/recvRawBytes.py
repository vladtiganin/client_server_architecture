def recvRawBytes(sock, lenth: int) -> bytes | None:
    data = b""
    while(len(data) < lenth):
        pock = sock.recv(lenth - len(data))
        if not pock: return None
        data += pock
    return data