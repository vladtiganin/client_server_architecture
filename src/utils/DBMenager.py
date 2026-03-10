import sqlite3
import logging
from src.utils.createLogger import createLogger
import apsw
import src
import hashlib
from src.utils.AESfuncs import decrypedByAES

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
            name TEXT UNIQUE,
            size TEXT,
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
            logger.debug(f"params : {params}")
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
        except sqlite3.IntegrityError as ex:
            raise sqlite3.IntegrityError(f"INUQUE constraint fault : {ex}")
        except Exception as ex:
            logger.exception("Exception during executing command: ")
            return None
        

    def readBLOB(self, table_name: str, column_name: str, row_id: int, chunk_size = 1024*1024):
        self.connection = apsw.Connection("bd.sqlite")
        cursor = self.connection.cursor()
        logger.info("Connect to database throw apsw")

        blob = self.connection.blob_open(
            database = "main",
            table = table_name,
            column = column_name,
            rowid=row_id,
            writeable=False
        )
        logger.info("Get BLOB object")

        try:
            offset = 0
            chunk_number = 1

            size = blob.length()
            logger.debug(f"BLOB size : {size}")

            while offset < size:
                blob.seek(offset)
                chunk = blob.read(min(chunk_size, size - offset))
                logger.debug(f"Chunck {chunk_number}: {len(chunk)} bytes")

                yield chunk

                offset += len(chunk)
                chunk_number += 1
        except Exception as ex:
            logger.exception(f"Error during extracting BLOB from db on {chunk_number} step : ")
        finally:
            blob.close()


    def writeAndHashBLOB(self, name: str, size: int, handler, signature) -> bool:
        size = size * 1.25
        self.connection = apsw.Connection("bd.sqlite")
        cursor = self.connection.cursor()
        logger.info("apsw connection good")

        user_id = cursor.execute('''
            SELECT id FROM Users WHERE login = ?  
        ''',(handler.client_login, )).fetchall()[0][0]
        logger.info("user id estracted")
        logger.debug(f"user id : {user_id}")

        cursor.execute('''
            INSERT INTO Files (name, size, data, user_id) 
                VALUES (?, ?, ZEROBLOB(?), ?) 
        ''', (name, size, size, user_id))
        logger.info("First insert good")

        row_id = self.connection.last_insert_rowid()
        logger.debug(f"Last inserted row {row_id}")

        blob = self.connection.blob_open(
            database="main",
            table="Files",
            column="data",
            rowid=row_id,
            writeable=True
        )
        logger.info("Blob object created")

        from src.utils.bytesFuncs import recvRawBytes
        sha = hashlib.sha256()
        salt = signature[:32]
        sha.update(salt)
        offset = 0
        while True:
            lenth = recvRawBytes(handler.conn, 4)
            if lenth is None or lenth == b'\x00\x00\x00\x00':
                break
            lenth = int.from_bytes(lenth, 'big')
            logger.debug(f"Lenth : {lenth}")
            data = decrypedByAES(handler.aes_key, recvRawBytes(handler.conn, lenth))
            logger.debug(f"Data : {data}")
            
            sha.update(data)

            offset += lenth
            blob.write(data)
            blob.seek(min(size, offset))
            logger.debug("Write to the BLOB")
        logger.debug("Out from loop")
    
        data_hash = sha.digest()

        if data_hash == signature[32:] : 
            logger.info("Data verified by signature")
            return True
        
        logger.info("Data not verified by signature, delete")
        cursor.execute('''
            DELETE FROM Files WHERE id = ?
        ''', (row_id, ))

        return False




    def __delete__(self):
        if hasattr(self, 'connection' and self.connection):
            self.connection.close()
        logger.info("DBManager deleted")



    

