import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def db_with_1_row(tmp_path):
    from server_app.db import DBManager

    db = DBManager(tmp_path / "test.sqlite")

    db.execute('''
        INSERT INTO Users(login, password_hash)
        VALUES (?, ?)
    ''', ('poop', b'\00\00\00\00'))

    return db


def test_db_manager_init_creates_database_file_and_tables(tmp_path):
    from server_app.db import DBManager
    import os

    db = DBManager(tmp_path / "test.sqlite")

    assert os.path.exists(tmp_path / "test.sqlite")

    users_table_exist = db.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='Users' 
    ''')
    assert users_table_exist[0][0] == 'Users'


    file_table_exist = db.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='Files' 
    ''')
    assert file_table_exist[0][0] == 'Files'


def test_execute_returns_rowcount_for_insert(tmp_path):
    from server_app.db import DBManager
    from Crypto.Random import get_random_bytes

    db = DBManager(tmp_path / "test.sqlite")

    res = db.execute('''
        INSERT INTO Users(login, password_hash)
        VALUES (?, ?)
    ''', ('poop', get_random_bytes(32)))

    assert res == 1


def test_execute_returns_rows_for_select(tmp_path):
    from server_app.db import DBManager
    from Crypto.Random import get_random_bytes

    db = DBManager(tmp_path / "test.sqlite")

    db.execute('''
        INSERT INTO Users(login, password_hash)
        VALUES (?, ?)
    ''', ('poop', get_random_bytes(32)))

    res = db.execute('''
        SELECT login, id FROM Users
    ''')

    assert res == [('poop', 1), ]


def test_execute_raises_integrity_error_for_unique_violation(tmp_path):
    from server_app.db import DBManager
    from Crypto.Random import get_random_bytes

    db = DBManager(tmp_path / "test.sqlite")

    db.execute('''
        INSERT INTO Users(login, password_hash)
        VALUES (?, ?)
    ''', ('poop', get_random_bytes(32)))

    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.execute('''
            INSERT INTO Users(login, password_hash)
            VALUES (?, ?)
        ''', ('poop', get_random_bytes(32)))


def test_execute_returns_none_on_generic_exception(tmp_path):
    from server_app.db import DBManager
    from Crypto.Random import get_random_bytes

    db = DBManager(tmp_path / "test.sqlite")


    res =db.execute('''
        INSERT INTO Users(login)
        VALUES (?, ?)
    ''', params='poop')

    assert res is None


def test_get_user_returns_row_for_existing_user(db_with_1_row):
    res = db_with_1_row.get_user("poop")

    assert res == (1, "poop", b"\00\00\00\00")


def test_get_user_returns_none_for_missing_user(db_with_1_row):
    res = db_with_1_row.get_user('poap')

    assert res is None


def test_get_user_id_returns_integer_for_existing_user(db_with_1_row):
    res = db_with_1_row.get_user_id('poop')
    assert res == 1


def test_get_user_id_raisebs_for_missing_user(db_with_1_row):
    with pytest.raises(ValueError):
        db_with_1_row.get_user_id('poqp')


