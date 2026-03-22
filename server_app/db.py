from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import apsw

from server_app.config import DB_PATH
from server_app.crypto import HashingSHA_256, create_logger


logger = create_logger(__name__)


class DBManager:
    def __init__(self, db_file_path: str | Path = DB_PATH):
        self.db_file_path = str(db_file_path)
        Path(self.db_file_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.db_file_path)
        self.__describe_db()

    def __describe_db(self) -> None:
        cursor = self.connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS Users(
                id INTEGER PRIMARY KEY,
                login TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL
            )
            """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login ON Users (login)")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS Files(
                id INTEGER PRIMARY KEY,
                name TEXT,
                size TEXT,
                data BLOB NOT NULL,
                user_id INTEGER NOT NULL,

                UNIQUE(name, user_id),

                FOREIGN KEY(user_id) REFERENCES Users(id)
                        ON UPDATE RESTRICT
            )
            """
        )

        self.connection.commit()

    def execute(self, command: str, params=None):
        cursor = self.connection.cursor()
        try:
            if params is not None:
                cursor.execute(command, params)
            else:
                cursor.execute(command)

            self.connection.commit()

            if command.strip().upper().startswith("SELECT"):
                return cursor.fetchall()
            return cursor.rowcount
        except sqlite3.IntegrityError as ex:
            raise sqlite3.IntegrityError(f"UNIQUE constraint fault: {ex}")
        except Exception:
            logger.exception("Exception during executing command")
            return None

    def get_user(self, login: str):
        result = self.execute(
            """
            SELECT id, login, password_hash
            FROM Users
            WHERE login = ?
            """,
            (login,),
        )
        return result[0] if result else None

    def get_user_id(self, login: str) -> int:
        user = self.get_user(login)
        if user is None:
            raise ValueError(f"User {login!r} not found")
        return user[0]

    def list_user_files(self, login: str):
        return self.execute(
            """
            SELECT Files.name, Files.size
            FROM Files
            INNER JOIN Users ON Users.id = Files.user_id
            WHERE Users.login = ?
            ORDER BY Files.name ASC
            """,
            (login,),
        )

    def get_user_file(self, login: str, file_name: str):
        result = self.execute(
            """
            SELECT Files.id, Files.name, Files.size
            FROM Files
            INNER JOIN Users ON Users.id = Files.user_id
            WHERE Users.login = ? AND Files.name = ?
            """,
            (login, file_name),
        )
        return result[0] if result else None

    def delete_user_file(self, login: str, file_name: str) -> int | None:
        user_id = self.get_user_id(login)
        return self.execute(
            """
            DELETE FROM Files
            WHERE name = ? AND user_id = ?
            """,
            (file_name, user_id),
        )

    def store_user_file(self, login: str, name: str, size: int, chunks, signature: bytes) -> tuple[bool, str]:
        connection = apsw.Connection(self.db_file_path)
        cursor = connection.cursor()

        user_row = cursor.execute(
            """
            SELECT id FROM Users WHERE login = ?
            """,
            (login,),
        ).fetchall()
        if not user_row:
            return False, "User not found"

        user_id = user_row[0][0]
        existing = cursor.execute(
            """
            SELECT 1 FROM Files WHERE name = ? AND user_id = ?
            """,
            (name, user_id),
        ).fetchall()
        if existing:
            return False, "For this user file already exists"

        cursor.execute(
            """
            INSERT INTO Files (name, size, data, user_id)
            VALUES (?, ?, ZEROBLOB(?), ?)
            """,
            (name, size, size, user_id),
        )
        row_id = connection.last_insert_rowid()

        blob = connection.blob_open(
            database="main",
            table="Files",
            column="data",
            rowid=row_id,
            writeable=True,
        )

        try:
            hasher = hashlib.sha256()
            salt = signature[:32]
            hasher.update(salt)
            written = 0

            for chunk in chunks:
                blob.write(chunk)
                hasher.update(chunk)
                written += len(chunk)

            if written != size:
                cursor.execute("DELETE FROM Files WHERE id = ?", (row_id,))
                return False, "Invalid file size"

            if hasher.digest() == signature[32:]:
                return True, "Data written"

            cursor.execute("DELETE FROM Files WHERE id = ?", (row_id,))
            return False, "Data broken"
        finally:
            blob.close()

    def iter_blob_chunks(self, row_id: int, chunk_size: int = 1024 * 1024):
        connection = apsw.Connection(self.db_file_path)
        blob = connection.blob_open(
            database="main",
            table="Files",
            column="data",
            rowid=row_id,
            writeable=False,
        )

        try:
            offset = 0
            size = blob.length()
            while offset < size:
                blob.seek(offset)
                chunk = blob.read(min(chunk_size, size - offset))
                yield chunk
                offset += len(chunk)
        finally:
            blob.close()

    def hash_blob(self, row_id: int, chunk_size: int = 1024 * 1024, salt: bytes | None = None) -> bytes:
        if salt is None:
            salt = HashingSHA_256.generate_salt()

        hasher = hashlib.sha256()
        hasher.update(salt)
        for chunk in self.iter_blob_chunks(row_id, chunk_size=chunk_size):
            hasher.update(chunk)
        return salt + hasher.digest()

    def close(self) -> None:
        if getattr(self, "connection", None) is not None:
            self.connection.close()

    def __del__(self):
        self.close()
