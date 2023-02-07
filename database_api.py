""" A module that contains functions to control the Hash API.

This module keeps the signature list up-to-date and clean.
The update is currently triggered manually, but on each update,
the doubles get removed from the list and the list gets sorted.

References -> https://virusshare.com
"""

import time
import sqlite3
from urllib.request import urlopen
from urllib.error import HTTPError
from urllib.error import URLError


class HashAPI:
    """
    This class will do the following tasks using the Virusshare API
        - Periodically check if new hash signatures are available
        - Remove Hashes that are found twice in files
        - If needed, find more specific data on a Hash
        - Update the Hash signatures
    """
    db_connection = None

    def __init__(self, db_location):
        print("Hasher initialized")
        """ Initializes the class setting the given parameters

        It creates an object that can be used to interact with the Virusshare API
        and the signatures' database.
        """

        try:
            self.db_connection = sqlite3.connect(db_location)
            self.init_table()
            self.update_db()
        except sqlite3.Error as e:
            raise sqlite3.Error(f"Connection to DB failed: {str(e)}") from e

    def init_table(self):
        print("Creating table...")
        sql = ''' CREATE TABLE IF NOT EXISTS signatures (
                     hash varchar(32) PRIMARY KEY,
                     file_nr varchar(5)
                     ); '''
        try:
            cur = self.db_connection.cursor()
            cur.execute(sql)
            self.db_connection.commit()
        except sqlite3.Error as e:
            print(f"SQL table not created: {str(e)}")

    def insert_hash(self, hash_str, file_nr):
        sql = ''' INSERT INTO signatures(hash, file_nr)
               VALUES (?, ?) '''

        try:
            cur = self.db_connection.cursor()
            cur.execute(sql, (hash_str, file_nr))
            self.db_connection.commit()
        except sqlite3.Error as e:
            print(f"Hash ({hash_str}) not inserted: {str(e)}")

    def insert_hashes(self, hashes):
        try:
            self.db_connection.executemany('INSERT INTO signatures(hash, file_nr) VALUES(?, ?)', hashes)
            self.db_connection.commit()
        except sqlite3.Error as e:
            print(f"Hashes not inserted: {str(e)}")

    def hash_exists(self, hash_str):
        sql = ''' SELECT hash FROM signatures
                 WHERE hash = ? '''

        cur = self.db_connection.cursor()
        cur.execute(sql, (hash_str,))
        rows = cur.fetchone()

        return bool(rows)

    def get_latest_file_nr(self):
        sql = ''' SELECT file_nr
                     FROM signatures
                     ORDER BY file_nr DESC
                     LIMIT 1; '''

        cur = self.db_connection.cursor()
        cur.execute(sql)

        try:
            return ''.join(map(str, cur.fetchone()))
        except TypeError:
            return "00000"

    def count_hashes(self):
        sql = ''' SELECT COUNT(hash)
                     FROM signatures '''

        cur = self.db_connection.cursor()
        cur.execute(sql)

        return ''.join(map(str, cur.fetchone()))

    def remove_hash(self, hash_str):
        sql = ''' DELETE FROM signatures 
                    WHERE hash = ? '''

        cur = self.db_connection.cursor()
        cur.execute(sql, (hash_str,))

    def update_db(self):
        print("Updating database...")
        big_tic = time.perf_counter()
        self.download_files()
        big_toc = time.perf_counter()
        print(f"Executed in {big_toc - big_tic:0.4f} seconds")
        print(f"Total hashes in DB: {self.count_hashes()}")

    def download_files(self):
        if not self.db_is_updated():
            print("Database not up-to-date!")
            file_nr = self.get_latest_file_nr()

            while True:
                try:
                    tic = time.perf_counter()
                    filename = f"VirusShare_{file_nr}.md5"
                    url = f"https://virusshare.com/hashfiles/{filename}"
                    file = urlopen(url)
                    hashes = []
                    for line in file:
                        line_n = str(line).replace("b'", "").replace("\\n'", "")
                        if not line_n.startswith("#"):
                            hashes.append((line_n, file_nr))
                    self.insert_hashes(hashes)
                    toc = time.perf_counter()
                    print(f"Downloaded {filename} in {toc - tic:0.4f} seconds")
                    file_nr = int(file_nr) + 1
                    file_nr = f'{file_nr:05d}'
                except HTTPError as err:
                    if err.code == 404:
                        print("No more files to download")
                        break
                    print(f"ERROR: {str(err)}")
                    break
        else:
            print("DB already up-to-date")

    def db_is_updated(self):
        """ Checks if the Database is up-to-date.

        It uses another function to retrieve the latest file_nr in the database.
        Then using that, it tries to increase it and reach the file with the new number.
        If the request is successful, it means the database is outdated, else its updated

        Returns:
            False - Database is NOT updated
            True - Database is updated

        """
        file_nr = self.get_latest_file_nr()
        if file_nr == 'None':
            return False

        try:
            return self._check_latest_file(file_nr)
        except HTTPError as err:
            if err.code == 404:
                print("Database is up-to-date")
                return True
        except URLError:
            print("Not connected to the Internet!")
            return True

    @staticmethod
    def _check_latest_file(file_nr):
        file_nr = int(file_nr) + 1
        file_nr = f'{file_nr:05d}'
        filename = f"VirusShare_{file_nr}.md5"
        url = f"https://virusshare.com/hashfiles/{filename}"
        urlopen(url)
        return False

    def close_connection(self):
        self.db_connection.close()
