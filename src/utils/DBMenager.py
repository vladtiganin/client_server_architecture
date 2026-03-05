import sqlite3
import logging
from src.utils.createLogger import createLogger
import os

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

class DBMenager:
    def __init__(self, db_file_path : str):
        self.db_file_path = db_file_path
        self.connection = self._connect()
        self.__describeDB()


    def _connect(self):
        self.connection = sqlite3.connect(self.db_file_path)
    

    def __describeDB(self) -> None:
        cursor = self.connection.cursor()

        cursor.execute("PRAGMA foreign_keys = ON")

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users(
            id INTEGER PRIMARY KEY,
            login TEXT NOT NULL,
            password_hash BLOB NOT NULL
        )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_login ON Users (login)')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Files(
            id INTEGER PRIMARY KEY,
            data BLOB NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES Users(id)
                    ON UPDATE RESTRICT   
        )
        ''')

        self.connection.commit()
