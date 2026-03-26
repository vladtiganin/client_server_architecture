from server_app.RSA import RSA, RSAKey

def test_known_rsa():
    pub = RSAKey(17, 3233)
    priv = RSAKey(2753, 3233)

    assert RSA.encrypt_with_key(65, pub) == 2790
    assert RSA.decrypt_with_key(2790, priv) == 65


def test_unknown_rsa_by_keys():
    rsa = RSA()
    rsa.generate_keys(128)

    msg = 123456789

    msg_encr = rsa.encrypt_with_key(msg, rsa.private_key)
    msg_decr = rsa.decrypt_with_key(msg_encr, rsa.public_key)

    assert msg == msg_decr


def test_unknown_rsa_bytes_by_keys():
    rsa = RSA()
    rsa.generate_keys(128)
 
    msg = (123456789).to_bytes(4, 'big')

    msg_encr = rsa.encrypt_bytes_with_key(msg, rsa.private_key)
    msg_decr = rsa.decrypt_bytes_with_key(msg_encr, rsa.public_key)

    assert msg == msg_decr


def test_unknown_rsa_bytes():
    rsa = RSA()
    rsa.generate_keys(128)
 
    msg = (123456789).to_bytes(4, 'big')

    msg_encr = rsa.encrypt_bytes(msg)
    msg_decr = rsa.decrypt_bytes(msg_encr)

    assert msg == msg_decr


def test_unknown_rsa():
    rsa = RSA()
    rsa.generate_keys(128)
 
    msg = 123456789

    msg_encr = rsa.encrypt(msg)
    msg_decr = rsa.decrypt(msg_encr)

    assert msg == msg_decr