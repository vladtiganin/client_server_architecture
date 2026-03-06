import sqlite3
import logging
from src.utils.createLogger import createLogger
import os

logger = createLogger(__name__)
logger.setLevel(logging.DEBUG)

class DBMenager:
    def __init__(self, db_file_path : str):
        logger.debug("DBMenager creating")
        self.db_file_path = db_file_path
        self.connection = sqlite3.connect(self.db_file_path)
        self.__describeDB()
        logger.debug("DBMenager created")


    def __describeDB(self) -> None:
        cursor = self.connection.cursor()

        cursor.execute("PRAGMA foreign_keys = ON")
        logger.debug("Add fk")

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users(
            id INTEGER PRIMARY KEY,
            login TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
        ''')
        logger.debug("Create Users ")


        cursor.execute('CREATE INDEX IF NOT EXISTS idx_login ON Users (login)')
        logger.debug("Create index ")


        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Files(
            id INTEGER PRIMARY KEY,
            data BLOB NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES Users(id)
                    ON UPDATE RESTRICT   
        )
        ''')
        logger.debug("Create Files ")


        self.connection.commit()


    def execute(self, command : str, params=None):
        cursor = self.connection.cursor()
        try:
            if params:
                cursor.execute(command, params)
            else:
                cursor.execute(command)

            self.connection.commit()

            if command.strip().upper().startswith("SELECT"):
                result = cursor.fetchall()
                logger.debug(f"SELECT returned {len(result)} rows")
                return result
            else:
                affected_rows = cursor.rowcount
                logger.debug(f"Affected rows: {affected_rows}")
                return affected_rows
            
        except Exception as ex:
            logger.exception("Exception during executing command: ")
            return None

        return cursor.fetchall()


    

