from unittest.mock import patch


@patch("pathlib.Path.exists")
def test_default_db_path_returns_project_db_when_not_in_docker(mock_exists):
    mock_exists.return_value = False

    from server_app.config import _default_db_path
    from pathlib import Path
    res = _default_db_path()

    BASE_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = BASE_DIR.parent

    assert res == PROJECT_ROOT / "server_app" / "bd.sqlite"


@patch("pathlib.Path.exists")
def test_default_db_path_returns_docker_path_when_in_docker(mock_exists):
    mock_exists.return_value = True

    from server_app.config import _default_db_path
    from pathlib import Path
    res = _default_db_path()

    assert res == Path("/data/bd.sqlite")


def test_env_values_override_defaults_after_reload(monkeypatch):
    monkeypatch.setenv("SERVER_HOST", "1.2.3.4")
    monkeypatch.setenv("SERVER_PORT", "1234")
    monkeypatch.setenv("SERVER_BACKLOG", "12")
    monkeypatch.setenv("SERVER_SOCKET_TIMEOUT", "12")
    monkeypatch.setenv("SERVER_DB_PATH", "poop/BD/bd.sqlite")
    monkeypatch.setenv("SERVER_LOG_DIR", "poop/LOG/*.log")

    import importlib
    from server_app import config
    importlib.reload(config)

    try:
        assert config.BIND_HOST == "1.2.3.4"
        assert config.PORT == 1234
        assert config.BACKLOG == 12
        assert config.SOCKET_TIMEOUT == 12.0

        from pathlib import Path
        assert config.DB_PATH == Path("poop/BD/bd.sqlite")
        assert config.LOG_DIR == Path("poop/LOG/*.log")
    finally:
        monkeypatch.undo()
        importlib.reload(config)

    