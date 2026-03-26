import pytest
from unittest.mock import patch, Mock
import os


@pytest.fixture
def simple_RSAKey():
    from server_app.RSA import RSAKey
    rsa_key = RSAKey(7, 187)
    return rsa_key


@pytest.fixture
def simple_pair_of_RSAKeys():
    from server_app.RSA import RSAKey
    pk_key = RSAKey(7,187)
    pr_key = RSAKey(23,187)
    return (pk_key, pr_key)


def test_create_logger_creates_file_handler_and_log_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("SERVER_LOG_DIR", str(tmp_path / "logs"))

    import importlib                    #мы перегружаем модули потому что после смены env переменных нам надо их занаво подтянуть 
    from server_app import config
    importlib.reload(config)
    from server_app import crypto
    importlib.reload(crypto)

    import logging
    try:
        logger = crypto.create_logger("a.b:c")
        assert os.path.isfile(crypto.LOG_DIR / "a.b_c.log")
        assert any(isinstance(h, logging.FileHandler) for h in logger.handlers)
    finally:
        monkeypatch.undo()
        importlib.reload(config)
        importlib.reload(crypto)


def test_create_logger_returns_same_logger_without_duplicate_handlers(monkeypatch, tmp_path):
    monkeypatch.setenv("SERVER_LOG_DIR", str(tmp_path / "logs"))

    import importlib                    
    from server_app import config
    importlib.reload(config)
    from server_app import crypto
    importlib.reload(crypto)

    try:
        logger = crypto.create_logger("a.b:c")
        logger = crypto.create_logger("a.b:c")
        assert len(logger.handlers) == 1
    finally:
        monkeypatch.undo()
        importlib.reload(config)
        importlib.reload(crypto)


def test_generate_salt_default_lenth():
    from server_app.crypto import HashingSHA_256
    assert len(HashingSHA_256.generate_salt()) == 32


def test_generate_salt_castom_lenth():
    from server_app.crypto import HashingSHA_256
    assert len(HashingSHA_256.generate_salt(20)) == 20


def test_hashing_bytes_with_explicit_salt_returns_salt_plus_sha256():
    from server_app.crypto import HashingSHA_256
    salt = HashingSHA_256.generate_salt(12)

    data = b"h" * 64

    from hashlib import sha256
    assert salt + sha256(salt + data).digest() == HashingSHA_256.hashingBytes(data, salt=salt)


def test_hashing_bytes_without_salt_returns_64_bytes():
    from server_app.crypto import HashingSHA_256

    data = b"h" * 64

    assert 64 == len(HashingSHA_256.hashingBytes(data))


def test_verify_hash_returns_true_for_matching_signature():
    from server_app.crypto import HashingSHA_256

    data = b"h" * 64
    salt = HashingSHA_256.generate_salt()
    signature = HashingSHA_256.hashingBytes(data, salt)

    assert HashingSHA_256.verifyHash(data, signature) is True


def test_verify_hash_returns_false_for_modified_payload():
    from server_app.crypto import HashingSHA_256

    data = b"h" * 64
    salt = HashingSHA_256.generate_salt()
    signature = HashingSHA_256.hashingBytes(data, salt)

    assert HashingSHA_256.verifyHash(data + b"b", signature) is False


def test_verify_hash_returns_false_for_modified_signature():
    from server_app.crypto import HashingSHA_256

    data = b"h" * 64
    salt = HashingSHA_256.generate_salt()
    signature = bytearray(HashingSHA_256.hashingBytes(data, salt))
    signature[33] = ord("b")

    assert HashingSHA_256.verifyHash(data, bytes(signature)) is False


def test_verify_hash_rsa_key_returns_true_for_matching_key_signature(simple_RSAKey):
    from server_app.crypto import HashingSHA_256
    salt = HashingSHA_256.generate_salt()

    from server_app.crypto import get_format_bytes_from_rsa_key
    from hashlib import sha256
    assert  HashingSHA_256.verifyHashRSAKey(simple_RSAKey, (salt + sha256(salt + get_format_bytes_from_rsa_key(simple_RSAKey)).digest())) is True


def test_verify_hash_rsa_key_returns_false_for_modified_key():
    from server_app.crypto import HashingSHA_256
    salt = HashingSHA_256.generate_salt()

    from server_app.crypto import get_format_bytes_from_rsa_key
    from server_app.RSA import RSAKey
    from hashlib import sha256
    assert  HashingSHA_256.verifyHashRSAKey(RSAKey(7, 187), (salt + sha256(salt + get_format_bytes_from_rsa_key(RSAKey(7, 182))).digest())) is False


def test_aes_encrypt_then_decrypt_returns_original_data():
    from Crypto.Random import get_random_bytes
    aes_key = get_random_bytes(32)

    data = b"poooop"

    from server_app.crypto import encrypedByAES, decrypedByAES
    assert data == decrypedByAES(aes_key, encrypedByAES(aes_key, data))


def test_aes_encrypt_uses_random_nonce():
    from Crypto.Random import get_random_bytes
    aes_key = get_random_bytes(32)

    data = b"poooop"

    from server_app.crypto import encrypedByAES, decrypedByAES
    assert encrypedByAES(aes_key, data)[8:] != encrypedByAES(aes_key, data)[8:]


def test_big_int_to_bytes_zero_returns_single_zero_byte():
    from server_app.crypto import big_int_to_bytes
    assert big_int_to_bytes(0) == b"\x00"


def test_big_int_to_bytes_and_bytes_to_big_int_are_inverse_for_positive_number():
    from server_app.crypto import big_int_to_bytes, bytes_to_big_int
    
    num = 123456789

    assert bytes_to_big_int(big_int_to_bytes(num)) == num


def test_big_int_to_bytes_respects_byte_order():
    from server_app.crypto import big_int_to_bytes
    assert big_int_to_bytes(1234, bytes_order='big') == (1234).to_bytes(2,'big')
    assert big_int_to_bytes(1234, bytes_order='little') == (1234).to_bytes(2, 'little')


def test_bytes_to_big_int_respects_byte_order():
    from server_app.crypto import bytes_to_big_int
    assert bytes_to_big_int(b"\x12\x34", bytes_order="big") != bytes_to_big_int(b"\x12\x34", bytes_order="little")


def test_recv_raw_bytes_reads_until_requested_length():
    from server_app.crypto import recv_raw_bytes

    fake_sock = Mock()
    fake_sock.recv.side_effect = [b"pp", b"bb", b"cc"]

    data = recv_raw_bytes(fake_sock, 6)

    assert data == b"ppbbcc"


def test_recv_raw_bytes_returns_empty_bytes_when_socket_closed_immediately():
    from server_app.crypto import recv_raw_bytes

    fake_sock = Mock()
    fake_sock.recv.side_effect = [b""]

    data = recv_raw_bytes(fake_sock, 6)

    assert data == b""
    

def test_recv_raw_bytes_raises_on_incomplete_stream():
    from server_app.crypto import recv_raw_bytes

    fake_sock = Mock()
    fake_sock.recv.side_effect = [b"pp", b"bb", b""]

    with pytest.raises(ConnectionError):
        recv_raw_bytes(fake_sock, 8)


def test_get_format_bytes_from_message_for_bytes_prefixes_length():
    from server_app.crypto import get_format_bytes_from_message
    mess = b"poop"
    bytes_mess = get_format_bytes_from_message(mess)

    assert bytes_mess == len(mess).to_bytes(4, 'big') + mess


def test_get_format_bytes_from_message_for_str_encodes_utf8_and_prefixes_length():
    from server_app.crypto import get_format_bytes_from_message
    mess = "poop"
    bytes_mess = get_format_bytes_from_message(mess)

    assert bytes_mess == len(mess.encode("utf-8")).to_bytes(4, 'big') + mess.encode("utf-8")


@patch("server_app.crypto.big_int_to_bytes")
def test_get_format_bytes_from_message_for_int_returns_raw_integer_bytes(mock_bitb):
    mock_bitb.return_value = "poop"

    from server_app.crypto import get_format_bytes_from_message
    num = 1234578

    assert get_format_bytes_from_message(num) == "poop"


def test_get_format_bytes_and_get_RSAKey_from_bytes(simple_RSAKey):
    from server_app.crypto import get_format_bytes_from_rsa_key, get_rsa_key_from_bytes

    key_bytes = get_format_bytes_from_rsa_key(simple_RSAKey)

    first_len = key_bytes[:4]
    second_len = key_bytes[4:8]
    first_key = key_bytes[8:8+int.from_bytes(first_len)]
    second_key = key_bytes[8+int.from_bytes(first_len):]

    fake_sock = Mock()
    fake_sock.recv.side_effect = [first_len, second_len, first_key, second_key]

    key = get_rsa_key_from_bytes(fake_sock)

    assert simple_RSAKey.first == key.first
    assert simple_RSAKey.second == key.second


@patch("server_app.crypto.HashingSHA_256.hashingBytes")
@patch("server_app.crypto.RSA.encrypt_bytes_with_key")
def test_create_signature(mock_enr, mock_hash):
    fake_hash = b"h" * 64
    fake_key = object()

    mock_enr.return_value = b"ENC"
    mock_hash.return_value = fake_hash

    from server_app.crypto import create_signature
    res = create_signature(fake_key, (b"ab", b"ba"))

    mock_enr.assert_called_once_with(fake_hash, fake_key)
    mock_hash.assert_called_once_with(b"abba")


def test_create_signature_roundtrip_with_real_rsa_key():
    from server_app.crypto import RSA
    rsa = RSA()
    rsa.generate_keys()

    data = b"h" * 64

    from server_app.crypto import create_signature
    signsture = create_signature(rsa.private_key, (data, ))

    decr_sig = RSA.decrypt_bytes_with_key(signsture, rsa.public_key)
    
    from server_app.crypto import HashingSHA_256
    assert HashingSHA_256.verifyHash(data, decr_sig) is True
    
    
@patch("server_app.crypto.RSA.decrypt_bytes_with_key")
def test_receive_signature_reads_length_and_decrypts_signature(mock_decr_rsa): 
    fake_sock = Mock()
    fake_sock.recv.side_effect = [(4).to_bytes(4, 'big'), b"poop"]

    mock_decr_rsa.return_value = "DECR"

    from server_app.crypto import receive_signature
    res = receive_signature(conn=fake_sock, key=object())

    assert res == "DECR"
    mock_decr_rsa.assert_called_once()
