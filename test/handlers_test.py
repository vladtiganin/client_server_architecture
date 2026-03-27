from unittest.mock import Mock, patch
import pytest


@patch("server_app.handlers.encrypedByAES")
@patch("server_app.handlers.get_format_bytes_from_message")
def test_send_response_encrypts_body_and_sends_code_plus_length_prefixed_payload(mock_gfbm, mock_encr):
    fake_handler = Mock(aes_key = b"k" * 32, conn = Mock())

    mock_encr.return_value = b"ENCR"
    mock_gfbm.return_value = b"FORM"

    from server_app.handlers import send_response
    send_response(fake_handler, 200, True, "OK")

    expected_body = {"success":True, "message":"OK"}

    mock_encr.assert_called_once_with(fake_handler.aes_key, repr(expected_body).encode())
    mock_gfbm.assert_called_once_with(b"ENCR")
    fake_handler.conn.sendall.assert_called_once_with(
        (200).to_bytes(4,'big') + b"FORM"
    )


@patch("server_app.handlers.send_response")
def test_unsure_authorized_returns_false_and_sends_error_when_user_missing(moke_sendrsp):
    from server_app.handlers import unsureAuthorized

    fake_handler = Mock(client_login = None)
    res = unsureAuthorized(fake_handler)

    moke_sendrsp.assert_called_once()
    assert res is False   


@patch("server_app.handlers.send_response")
def test_unsure_authorized_returns_true_when_user_present(moke_sendrsp):
    from server_app.handlers import unsureAuthorized

    fake_handler = Mock(client_login = "poop")
    res = unsureAuthorized(fake_handler)

    moke_sendrsp.assert_not_called()
    assert res is True  


@patch("server_app.handlers.recv_raw_bytes", return_value = b"RECV_BYTES")
@patch("server_app.handlers.decrypedByAES", 
       return_value = (len(b"vlad").to_bytes(4, "big") +
                       b"vlad" +
                       len(b"poop").to_bytes(4, "big") +
                       b"poop"))
def test_recv_lp_parses_login_and_password_from_encrypted_payload(mock_decr, mock_rrb):
    from server_app.handlers import recv_lp
    
    fake_handler = Mock(conn = Mock())
    login, password = recv_lp(fake_handler)

    assert login == b"vlad"
    assert password == b"poop"


@patch("server_app.handlers.recv_raw_bytes", return_value = b"RECV_BYTES")
@patch("server_app.handlers.decrypedByAES", 
       return_value = (len(b"file_1").to_bytes(4, "big") +
                       b"file_1" +
                       (5).to_bytes(4, "big")))
def test_recv_metadata_parses_file_name_and_size(mock_decr, mock_rrb):
    from server_app.handlers import recv_metadata

    file_name, file_size = recv_metadata(object(), object())

    assert file_name == "file_1"
    assert file_size == 5


@patch("server_app.handlers.recv_raw_bytes")
@patch("server_app.handlers.decrypedByAES", return_value = b"_ENCR_")
def test_iter_plain_chunks_yields_all_decrypted_chunks_until_zero_length_marker(mock_decr, mock_rrb):
    from server_app.handlers import iter_plain_chunks

    mock_rrb.side_effect= [
        (1).to_bytes(4, 'big'), b"\01",
        (1).to_bytes(4, 'big'), b"\01",
        (1).to_bytes(4, 'big'), b"\01",
        b"\x00\x00\x00\x00"
    ]

    data = b""
    for chunk in iter_plain_chunks(object(), object()):
        data += chunk

    assert data == b"_ENCR__ENCR__ENCR_"


@patch("server_app.handlers.recv_raw_bytes")
@patch("server_app.handlers.decrypedByAES", return_value = b"_ENCR_")
def test_iter_plain_chunks_stops_when_recv_raw_bytes_returns_empty(mock_decr, mock_rrb):
    from server_app.handlers import iter_plain_chunks

    mock_rrb.side_effect= [b""]

    data = b""
    for chunk in iter_plain_chunks(object(), object()):
        data += chunk

    assert data == b""


def test_client_handler_init_raises_for_none_socket():
    from server_app.handlers import ClientHandler
    with pytest.raises(ValueError):
        ClientHandler(conn = None)


def test_client_handler_init_sets_default_fields():
    from server_app.handlers import ClientHandler
    handler = ClientHandler(object())

    assert handler.aes_key is None
    assert handler.client_login is None
    assert handler._client_pubk is None


@patch("server_app.handlers.ClientHandler._ClientHandler__generate_aes_exchange_message")
@patch("server_app.handlers.HashingSHA_256.verifyHashRSAKey")
@patch("server_app.handlers.receive_signature")
@patch("server_app.handlers.get_rsa_key_from_bytes")
def test_handshake_reads_client_key_verifies_signature_generates_aes_and_sends_exchange_message(
    mock_get_key_from_bts, 
    mock_recv_sign, 
    mock_ver_key,
    mock_ex_aes_msg):
    from server_app.RSA import RSAKey
    from server_app.handlers import ClientHandler

    mock_get_key_from_bts.return_value = RSAKey(7, 187)
    mock_recv_sign.return_value = b"SIGN"
    mock_ver_key.return_value = True
    mock_ex_aes_msg.return_value = b"READY"

    fake_sock = Mock()
    handler = ClientHandler(fake_sock)
    handler.handshake()

    mock_get_key_from_bts.assert_called_once_with(fake_sock)
    mock_recv_sign.assert_called_once_with(fake_sock, handler._client_pubk)
    mock_ver_key.assert_called_once_with(handler._client_pubk, b"SIGN")
    mock_ex_aes_msg.assert_called_once()
    fake_sock.sendall.assert_called_once_with(b"READY")
    assert handler.aes_key is not None
    assert len(handler.aes_key) == 32


@patch("server_app.handlers.HashingSHA_256.verifyHashRSAKey")
@patch("server_app.handlers.receive_signature")
@patch("server_app.handlers.get_rsa_key_from_bytes")
def test_handshake_raises_when_client_key_signature_is_invalid(
    mock_get_key_from_bts, 
    mock_recv_sign, 
    mock_ver_key):
    from server_app.RSA import RSAKey
    from server_app.handlers import ClientHandler

    mock_get_key_from_bts.return_value = RSAKey(7, 187)
    mock_recv_sign.return_value = "SIGN"
    mock_ver_key.return_value = False

    handler = ClientHandler(object())
    with pytest.raises(ValueError):
        handler.handshake()


@patch("server_app.handlers.RSA.encrypt_bytes_with_key", side_effect = [b"SIGN", b"DATA"])
@patch("server_app.handlers.HashingSHA_256.hashingBytes", return_value = b"HASHED")
def test_generate_aes_exchange_message_builds_two_length_prefixed_encrypted_parts(mock_hashing, mock_encr):
    from server_app.handlers import ClientHandler

    handler = ClientHandler(object())
    res = handler._ClientHandler__generate_aes_exchange_message()
    
    assert res == len(b"DATA").to_bytes(4, 'big') + b"DATA" + len(b"SIGN").to_bytes(4, 'big') + b"SIGN"
    


@patch("server_app.handlers.handle_pst")
@patch("server_app.handlers.handle_lis")
@patch("server_app.handlers.handle_get")
@patch("server_app.handlers.handle_del")
@patch("server_app.handlers.handle_aut")
@patch("server_app.handlers.handle_reg")
@patch("server_app.handlers.recv_raw_bytes", side_effect = [
    b'PST', b""
    b'LIS', b""
    b'GET', b""
    b'DEL', b""
    b'AUT', b""
    b'REG', b""
    ])
def test_start_communication_loop_routes_each_mode_to_correct_handler(
    mock_recv_bts,
    mock_reg,
    mock_aut,
    mock_del,
    mock_get,
    mock_lis,
    mock_pst,
    ):
    from server_app.handlers import ClientHandler
    handler = ClientHandler(object())
    handler.start_communication_loop()


    mock_pst.assert_called_once_with(handler)
    mock_get.assert_called_once_with(handler)
    mock_del.assert_called_once_with(handler)
    mock_aut.assert_called_once_with(handler)
    mock_reg.assert_called_once_with(handler)
    mock_lis.assert_called_once_with(handler)


@patch("server_app.handlers.handle_aut", return_value = b"poop")
@patch("server_app.handlers.handle_reg", return_value = b"poop")
@patch("server_app.handlers.recv_raw_bytes", side_effect = [
    b'AUT', b""
    b'REG', b""
    ])
def test_start_communication_loop_sets_client_login_from_aut_and_reg_results(
    mock_recv_bts,
    mock_reg,
    mock_aut,
):
    from server_app.handlers import ClientHandler
    
    def aut_side_effect(arg):
        assert handler.client_login is None
        return "login_form_aut"
    
    def reg_side_effecr(arg):
        assert handler.client_login == "login_form_aut"
        return "login_from_reg"

    mock_aut.side_effect = aut_side_effect
    mock_reg.side_effect = reg_side_effecr

    handler = ClientHandler(object())
    handler.start_communication_loop()

    assert handler.client_login == "login_from_reg"












