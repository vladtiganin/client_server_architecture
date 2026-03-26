import pytest
from unittest.mock import Mock, patch


def data_generator(data, size):
    for i in range(0, len(data), size):
        yield data[i:i + size]


@pytest.fixture
def filled_in_db(tmp_path):
    from server_app.db import DBManager

    db = DBManager(tmp_path / "test.sqlite")

    db.execute('''
        INSERT INTO Users(login, password_hash)
        VALUES (?, ?)
    ''', ('poop', b'\00\00\00\00'))

    db.execute('''
        INSERT INTO Users(login, password_hash)
        VALUES (?, ?)
    ''', ('hhhh', b'\01\01\01\01'))

    db.execute('''
        INSERT INTO Files(name, size, user_id, data)
        VALUES (?,?,?,?),
               (?,?,?,?),
               (?,?,?,?) 
    ''',(
        "file_1", '1111', 1, "Hello".encode('utf-8'),
        "file_2", '2222', 1, "World".encode("utf-8"),
        "file_3", '3333', 2, "Python".encode("utf-8")
    ))

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


def test_get_user_returns_row_for_existing_user(filled_in_db):
    res = filled_in_db.get_user("poop")

    assert res == (1, "poop", b"\00\00\00\00")


def test_get_user_returns_none_for_missing_user(filled_in_db):
    res = filled_in_db.get_user('poap')

    assert res is None


def test_get_user_id_returns_integer_for_existing_user(filled_in_db):
    res = filled_in_db.get_user_id('poop')
    assert res == 1


def test_get_user_id_raisebs_for_missing_user(filled_in_db):
    with pytest.raises(ValueError):
        filled_in_db.get_user_id('poqp')


def test_list_user_files_returns_only_files_of_requested_user_sorted_by_name(filled_in_db):
    res = filled_in_db.list_user_files("poop")

    assert len(res) == 2
    assert (res[0][0] == 'file_1') and (res[0][1] == '1111')
    assert (res[1][0] == 'file_2') and (res[1][1] == '2222')
    
    names = [i[0] for i in res]
    assert names == sorted(names)


def test_get_user_file_returns_file_row_for_existing_file(filled_in_db):
    res = filled_in_db.get_user_file('poop', 'file_1')
    assert res == (1, 'file_1', '1111')


def test_get_user_file_returns_none_for_missing_file(filled_in_db):
    res = filled_in_db.get_user_file('poop', 'kaka')
    assert res is None


def test_delete_user_file_removes_existing_file(filled_in_db):
    res = filled_in_db.delete_user_file('poop', 'file_1')
    assert res == 1


def test_delete_user_file_returns_zero_for_missing_file(filled_in_db):
    res = filled_in_db.delete_user_file('poop', 'fvuybjile_1')
    assert res == 0


def test_store_user_file_writes_blob_and_returns_success(filled_in_db):
    from server_app.crypto import HashingSHA_256
    from hashlib import sha256

    data = b"1 2 3 4 5 6 7 8 9"
    salt = HashingSHA_256.generate_salt()
    signature = salt + sha256(salt + data).digest()

    res = filled_in_db.store_user_file(
        login='poop',
        name='file_3',
        size=len(data),
        chunks=data_generator(data, 2),
        signature=signature
    )

    assert res == (True, "Data written")

    extracted_data = filled_in_db.execute('''
        SELECT * FROM Files
        WHERE user_id = 1 
    ''')
    
    assert (4, 'file_3', str(len(data)), data, 1) in extracted_data


def test_store_user_file_returns_user_not_found_for_missing_login(filled_in_db):
    from server_app.crypto import HashingSHA_256
    from hashlib import sha256

    data = b"1 2 3 4 5 6 7 8 9"
    salt = HashingSHA_256.generate_salt()
    signature = salt + sha256(salt + data).digest()

    res = filled_in_db.store_user_file(
        login='ppop',
        name='file_3',
        size=len(data),
        chunks=data_generator(data, 2),
        signature=signature
    )

    assert res == (False, "User not found")


def test_store_user_file_rejects_duplicate_file_name_for_same_user(filled_in_db):
    from server_app.crypto import HashingSHA_256
    from hashlib import sha256

    data = b"1 2 3 4 5 6 7 8 9"
    salt = HashingSHA_256.generate_salt()
    signature = salt + sha256(salt + data).digest()

    res = filled_in_db.store_user_file(
        login='poop',
        name='file_2',
        size=len(data),
        chunks=data_generator(data, 2),
        signature=signature
    )

    assert res == (False, "For this user file already exists")


def test_store_user_file_returns_invalid_file_size_and_rolls_back_row(filled_in_db):
    from server_app.crypto import HashingSHA_256
    from hashlib import sha256

    data = b"1 2 3 4 5 6 7 8 9"
    salt = HashingSHA_256.generate_salt()
    signature = salt + sha256(salt + data).digest()

    res = filled_in_db.store_user_file(
        login='poop',
        name='file_3',
        size=99,
        chunks=data_generator(data, 2),
        signature=signature
    )

    assert res == (False, "Invalid file size")

    extracted_data = filled_in_db.execute('''
        SELECT * FROM Files
        WHERE user_id = 1 
    ''')
    
    assert (4, 'file_3', str(99), data, 1) not in extracted_data


def test_store_user_file_returns_data_broken_and_rolls_back_row(filled_in_db):

    data = b"1 2 3 4 5 6 7 8 9"

    res = filled_in_db.store_user_file(
        login='poop',
        name='file_3',
        size=len(data),
        chunks=data_generator(data, 2),
        signature=b"qq"
    )

    assert res == (False, "Data broken")

    extracted_data = filled_in_db.execute('''
        SELECT * FROM Files
        WHERE user_id = 1 
    ''')
    
    assert (4, 'file_3', str(len(data)), data, 1) not in extracted_data


def test_iter_blob_chunks_yields_full_blob_in_requested_chunk_size(filled_in_db):
    extracted_data = b""
    for chunk in filled_in_db.iter_blob_chunks(1, 2):
        extracted_data = extracted_data + chunk

    assert extracted_data == b"Hello"


def test_hash_blob_with_explicit_salt_returns_expected_signature(filled_in_db):
    from server_app.crypto import HashingSHA_256
    from hashlib import sha256

    salt = HashingSHA_256.generate_salt()
    assert filled_in_db.hash_blob(1, 2, salt) == salt + sha256(salt + b"Hello").digest()


def test_hash_blob_without_salt_returns_64_bytes(filled_in_db):
    assert len(filled_in_db.hash_blob(1, 2)) == 64


def test_close_can_be_called_twice_without_error(tmp_path):
    from server_app.db import DBManager

    db = DBManager(tmp_path / "test.sqlite")
    db.close()
    db.close()








