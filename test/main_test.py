from unittest.mock import Mock, patch, call
import pytest


@patch("server_app.main.socket")
def test_main_creates_socket_binds_listens_and_sets_timeout(mock_socket):
    from server_app.main import main, BACKLOG, BIND_HOST, PORT, SOCKET_TIMEOUT

    fake_sock = Mock()

    mock_socket.socket.return_value = fake_sock
    fake_sock.accept.side_effect = KeyboardInterrupt
    main()


    mock_socket.socket.assert_called_once()
    fake_sock.bind.assert_called_once_with((BIND_HOST, PORT))
    fake_sock.listen.assert_called_once_with(BACKLOG)
    fake_sock.settimeout.assert_called_once_with(SOCKET_TIMEOUT) 


@patch("server_app.main.threading")
@patch("server_app.main.socket")
def test_main_accepts_connection_and_spawns_thread_for_client_handler(mock_socket, mock_thread):
    from server_app.main import main
    from server_app.handlers import clientHandler
    
    fake_sock = Mock()

    mock_socket.socket.return_value = fake_sock
    fake_conn = object()
    fake_addr = object()
    fake_sock.accept.return_value = [fake_conn,fake_addr]

    fake_thread = Mock()
    mock_thread.Thread.return_value = fake_thread
    fake_thread.start.side_effect = KeyboardInterrupt

    main()

    mock_thread.Thread.assert_called_once_with(target=clientHandler, args=(fake_conn, ), daemon=True)


@patch("server_app.main.threading")
@patch("server_app.main.socket")
def test_main_ignores_timeout_error_and_continues_loop(mock_socket, mock_thread):
    from server_app.main import main
    
    fake_sock = Mock()

    mock_socket.socket.return_value = fake_sock
    fake_conn = object()
    fake_addr = object()
    fake_sock.accept.side_effect = [TimeoutError(), KeyboardInterrupt()]

    fake_thread = Mock()
    mock_thread.Thread.return_value = fake_thread

    main()

    mock_thread.Thread.assert_not_called()


@patch("server_app.main.threading")
@patch("server_app.main.socket")
def test_main_joins_threads_and_closes_socket_on_exit(mock_socket, mock_thread):
    from server_app.main import main

    fake_sock = Mock()

    mock_socket.socket.return_value = fake_sock
    fake_conn = object()
    fake_addr = object()
    fake_sock.accept.side_effect = [(fake_conn, fake_addr), KeyboardInterrupt]

    fake_thread = Mock()
    mock_thread.Thread.return_value = fake_thread
    
    main()

    fake_thread.join.assert_any_call()
    fake_sock.close.assert_called_once()










