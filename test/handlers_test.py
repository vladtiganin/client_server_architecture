from unittest.mock import Mock, patch, call
import pytest
from sqlite3 import IntegrityError


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


@patch("server_app.handlers.recv_raw_bytes", return_value = b"GEL")
def test_start_communication_loop_raises_for_invalid_mode(mock_recv):
    from server_app.handlers import ClientHandler

    handler = ClientHandler(object())
    with pytest.raises(ValueError):
        handler.start_communication_loop()


@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = False)
@patch("server_app.handlers.send_response")
def test_handle_aut_returns_none_and_400_when_request_signature_is_invalid(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
):
    from server_app.handlers import handle_aut
    handler = Mock(conn = object(), _client_pubk = object())
    res = handle_aut(handler)
    assert res is None
    mock_send_resp.assert_called_once_with(handler,400,False,"Received broken data")


@patch("server_app.handlers.DBManager.get_user", return_value = None)
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.send_response")
def test_handle_aut_returns_none_when_user_not_found(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
    mock_get_user
):
    from server_app.handlers import handle_aut

    handler = Mock(conn = object(), _client_pubk = object())
    res = handle_aut(handler)
    assert res is None
    mock_send_resp.assert_called_once_with(handler, 200, False, "Invalid login or password")


@patch("server_app.handlers.DBManager.get_user", return_value = b"poop")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", side_effect = [True, False])
@patch("server_app.handlers.send_response")
def test_handle_aut_returns_none_when_password_hash_does_not_match(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
    mock_get_user
):
    from server_app.handlers import handle_aut

    handler = Mock(conn = object(), _client_pubk = object())
    res = handle_aut(handler)

    assert res is None
    mock_send_resp.assert_called_once_with(handler, 200, False, "Invalid login or password or broken data")


@patch("server_app.handlers.DBManager.get_user", return_value = (b"vlad", b"poop", b"h"*32))
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.send_response")
def test_handle_aut_returns_login_and_sends_success_for_valid_credentials(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
    mock_get_user
):
    from server_app.handlers import handle_aut

    handler = Mock(conn = object(), _client_pubk = object())
    res = handle_aut(handler)

    assert res == b"poop"
    mock_send_resp.assert_called_once_with(handler, 200, True, "Authorized")


@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = False)
@patch("server_app.handlers.send_response")
def test_handle_reg_returns_none_when_request_signature_is_invalid(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
):
    from server_app.handlers import handle_reg

    handler = Mock(conn = object(), _client_pubk = object())
    res = handle_reg(handler)

    assert res is None
    mock_send_resp.assert_called_once_with(handler, 200, False, "Received broken data")


@patch("server_app.handlers.DBManager.execute", side_effect = IntegrityError())
@patch("server_app.handlers.HashingSHA_256.hashingBytes", return_value = b"HASH")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.send_response")
def test_handle_reg_returns_none_and_409_when_login_already_exists(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
    mock_hash,
    mock_db_exec
):
    from server_app.handlers import handle_reg

    handler = Mock(conn = object(), _client_pubk = object())

    res = handle_reg(handler)

    assert res is None
    mock_send_resp.assert_called_once_with(handler, 409, False, "Already exists")


@patch("server_app.handlers.DBManager.execute", return_value = None)
@patch("server_app.handlers.HashingSHA_256.hashingBytes", return_value = b"HASH")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.send_response")
def test_handle_reg_returns_none_and_500_when_insert_failed(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
    mock_hash,
    mock_db_exec
):
    from server_app.handlers import handle_reg

    handler = Mock(conn = object(), _client_pubk = object())

    res = handle_reg(handler)

    assert res is None
    mock_send_resp.assert_called_once_with(handler, 500, False, "Something goes wrong, try again later")


@patch("server_app.handlers.DBManager.execute", return_value = b"poop")
@patch("server_app.handlers.HashingSHA_256.hashingBytes", return_value = b"HASH")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.recv_lp", return_value = (b"vlad", b"poop"))
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.send_response")
def test_handle_reg_returns_login_and_sends_success_when_user_created(
    mock_send_resp,
    mock_ver_hash,
    mock_recv_lp,
    mock_recv_sign,
    mock_hash,
    mock_db_exec
):
    from server_app.handlers import handle_reg

    handler = Mock(conn = object(), _client_pubk = object())

    res = handle_reg(handler)

    assert res == "vlad"
    mock_send_resp.assert_called_once_with(handler, 200, True, "User registered")


@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.create_signature")
@patch("server_app.handlers.encrypedByAES")
@patch("server_app.handlers.unsureAuthorized", return_value = False)
def test_handle_lis_returns_immediately_for_unauthorized_user(
    mock_uns_aut,
    mock_enc,
    mock_cr_sig,
    mock_db,
    ):
    from server_app.handlers import handle_lis

    handle_lis(object())

    mock_db.assert_not_called()
    mock_cr_sig.assert_not_called()
    mock_enc.assert_not_called()


@patch("server_app.handlers.get_format_bytes_from_message", return_value = b"FORMATTED")
@patch("server_app.handlers.send_response")
@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.create_signature")
@patch("server_app.handlers.encrypedByAES")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_lis_sends_success_status_then_signature_and_encrypted_list(
    mock_uns_aut,
    mock_enc,
    mock_cr_sig,
    mock_db,
    mock_send_resp,
    mock_gfbfm
):
    from server_app.handlers import handle_lis

    handler = Mock(conn = Mock())

    mock_db.return_value.list_user_files.return_value = Mock(return_value=(b"LISTED", b""))

    handle_lis(handler)

    mock_send_resp.assert_called_once_with(handler, 200, True, "List sent")
    handler.conn.sendall.assert_called_once_with(b"FORMATTEDFORMATTED")


@patch("server_app.handlers.unsureAuthorized", return_value = False)
def test_handle_del_returns_immediately_for_unauthorized_user(
    mock_uns_aut
):
    from server_app.handlers import handle_del

    res = handle_del(object())

    assert res is None


@patch("server_app.handlers.send_response")
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = False)
@patch("server_app.handlers.decrypedByAES", return_value = b"DECR")    
@patch("server_app.handlers.recv_raw_bytes", return_value = b"\00\00\00\00")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_del_sends_400_when_signature_is_invalid(
    mock_uns_aut,
    mock_recv_sign,
    mock_recv_bts,
    mock_decr,
    mock_ver,
    mock_send_resp
):
    from server_app.handlers import handle_del

    handler = Mock(conn = object())
    handle_del(handler)

    mock_send_resp.assert_called_once_with(handler, 400, False, "Data broken")


@patch("server_app.handlers.DBManager.get_user_file", return_value = None)
@patch("server_app.handlers.send_response")
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.decrypedByAES", return_value = b"DECR")    
@patch("server_app.handlers.recv_raw_bytes", return_value = b"\00\00\00\00")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_del_sends_not_found_when_file_missing(
    mock_uns_aut,
    mock_recv_sign,
    mock_recv_bts,
    mock_decr,
    mock_ver,
    mock_send_resp,
    mock_db_get_file
):
    from server_app.handlers import handle_del

    handler = Mock(conn = object())
    handle_del(handler)

    mock_send_resp.assert_called_once_with(handler, 200, False, "File not found")


@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.send_response")
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.decrypedByAES", return_value = b"DECR")    
@patch("server_app.handlers.recv_raw_bytes", return_value = b"\00\00\00\00")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_del_deletes_file_and_sends_success_when_file_exists(
    mock_uns_aut,
    mock_recv_sign,
    mock_recv_bts,
    mock_decr,
    mock_ver,
    mock_send_resp,
    mock_db
):
    from server_app.handlers import handle_del

    handler = Mock(conn = object(), client_login = "vlad")
    mock_db.return_value.get_user_file.return_value = "file"
    handle_del(handler)

    mock_db.return_value.delete_user_file.assert_called_once_with("vlad", "DECR")
    mock_send_resp.assert_called_once_with(handler, 200, True, "File deleted")


@patch("server_app.handlers.DBManager.store_user_file")
@patch("server_app.handlers.unsureAuthorized", return_value = False)
def test_handle_pst_returns_immediately_for_unauthorized_user(
    mock_uns_aut,
    mock_db_store,
):
    from server_app.handlers import handle_pst

    res = handle_pst(object())

    assert res is None
    mock_db_store.assert_not_called()


@patch("server_app.handlers.send_response")
@patch("server_app.handlers.iter_plain_chunks", return_value = "ITER")
@patch("server_app.handlers.recv_metadata", return_value = ["file", 10])
@patch("server_app.handlers.receive_signature", return_value = "SIGN")
@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_pst_passes_metadata_chunks_and_signature_to_db(
    mock_uns_aut,
    mock_db,
    mock_recv_sign,
    mock_recv_met,
    mock_iter,
    mock_send_resp
):
    from server_app.handlers import handle_pst

    handler = Mock(conn = object, client_login = "vlad")
    mock_db.return_value.store_user_file.return_value = [False, "mess"]

    handle_pst(handler)


    mock_db.return_value.store_user_file.assert_called_once_with(
        "vlad",
        "file",
        10,
        "ITER",
        "SIGN"
    )


@patch("server_app.handlers.send_response")
@patch("server_app.handlers.iter_plain_chunks", return_value = "ITER")
@patch("server_app.handlers.recv_metadata", return_value = ["file", 10])
@patch("server_app.handlers.receive_signature", return_value = "SIGN")
@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_pst_sends_200_on_success(
    mock_uns_aut,
    mock_db,
    mock_recv_sign,
    mock_recv_met,
    mock_iter,
    mock_send_resp
):
    from server_app.handlers import handle_pst

    handler = Mock(conn = object, client_login = "vlad")
    mock_db.return_value.store_user_file.return_value = [False, "mess"]

    handle_pst(handler)

    mock_send_resp.assert_called_once_with(handler, 400, False, "mess")

@patch("server_app.handlers.receive_signature", return_value = "SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = False)
def test_handle_get_returns_immediately_for_unauthorized_user(
    mock_uns_aut,
    mock_recv_sign,
):
    from server_app.handlers import handle_get

    handle_get(object())

    mock_recv_sign.assert_not_called()


@patch("server_app.handlers.send_response")
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = False)
@patch("server_app.handlers.decrypedByAES", return_value = b"DECR")    
@patch("server_app.handlers.recv_raw_bytes", return_value = b"\00\00\00\00")
@patch("server_app.handlers.receive_signature", return_value = "SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_get_sends_400_when_signature_is_invalid(
    mock_uns_aut,
    mock_recv_sign,
    mock_recv_bts,
    mock_decr,
    mock_ver,
    mock_send_resp
):
    from server_app.handlers import handle_get

    handler = Mock(conn=object, client_login="vlad")
    handle_get(handler)

    mock_send_resp.assert_called_once_with(handler, 400, False, "Data broken")


@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.send_response")
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.decrypedByAES", return_value = b"DECR")    
@patch("server_app.handlers.recv_raw_bytes", return_value = b"\00\00\00\00")
@patch("server_app.handlers.receive_signature", return_value = "SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_get_sends_not_found_when_file_missing(
    mock_uns_aut,
    mock_recv_sign,
    mock_recv_bts,
    mock_decr,
    mock_ver,
    mock_send_resp,
    mock_db
):
    from server_app.handlers import handle_get

    handler = Mock(conn=object, client_login="vlad")
    mock_db.return_value.get_user_file.return_value = None

    handle_get(handler)

    mock_send_resp.assert_called_once_with(handler, 200, False, "File not found")


@patch("server_app.handlers.get_format_bytes_from_message", return_value = b"FORMATTED")
@patch("server_app.handlers.encrypedByAES", return_value = b"AES_ENCR")
@patch("server_app.handlers.RSA.encrypt_bytes_with_key", return_value = b"RSA_ENCR")
@patch("server_app.handlers.DBManager")
@patch("server_app.handlers.send_response")
@patch("server_app.handlers.HashingSHA_256.verifyHash", return_value = True)
@patch("server_app.handlers.decrypedByAES", return_value = b"DECR")    
@patch("server_app.handlers.recv_raw_bytes", return_value = b"\00\00\00\00")
@patch("server_app.handlers.receive_signature", return_value = b"SIGN")
@patch("server_app.handlers.unsureAuthorized", return_value = True)
def test_handle_get_streams_metadata_all_chunks_zero_terminator_and_final_status(
    mock_uns_aut,
    mock_recv_sign,
    mock_recv_bts,
    mock_decr,
    mock_ver,
    mock_send_resp,
    mock_db,
    mock_rsa_encr,
    mock_aes_encr,
    mock_gfbfm
):
    from server_app.handlers import handle_get

    handler = Mock(conn=Mock(), client_login="vlad")
    mock_db.return_value.get_user_file.return_value = [1,"file", 10]
    mock_db.return_value.hash_blob.return_value = b"HASH"
    mock_db.return_value.iter_blob_chunks.return_value = [b'I', b'T', b'E', b'R']

    handle_get(handler)


    mock_send_resp.assert_any_call(handler, 200, True, "File exists, start streaming")
    handler.conn.sendall.assert_has_calls([
        call(b"FORMATTEDFORMATTEDFORMATTED"),
        call(b"FORMATTED"),
        call(b"FORMATTED"),
        call(b"FORMATTED"),
        call(b"FORMATTED"),
        call((0).to_bytes(4, "big"))
        ])
    mock_send_resp.assert_any_call(handler, 200, True, "Data sent")
    
    













