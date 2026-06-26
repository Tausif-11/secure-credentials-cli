import sqlite3

class VaultDB:
    def __init__(self, db_path="vault.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        """
        Initializes the schema. Stores unique binary blobs 
        for encryption nonces, salts, and ciphertexts.
        """
        # Table storing the master login validation criteria
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_auth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt BLOB NOT NULL,
                verification_hash BLOB NOT NULL
            )
        ''')
        # Table storing the actual credential payloads
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                nonce BLOB NOT NULL,
                encrypted_password BLOB NOT NULL
            )
        ''')
        self.conn.commit()

    def get_auth_record(self):
        self.cursor.execute("SELECT salt, verification_hash FROM master_auth LIMIT 1")
        return self.cursor.fetchone()

    def save_auth_record(self, salt: bytes, verification_hash: bytes):
        self.cursor.execute(
            "INSERT INTO master_auth (salt, verification_hash) VALUES (?, ?)",
            (salt, verification_hash)
        )
        self.conn.commit()

    def add_credential(self, service: str, username: str, nonce: bytes, encrypted_password: bytes):
        self.cursor.execute(
            """INSERT OR REPLACE INTO credentials (service, username, nonce, encrypted_password) 
               VALUES (?, ?, ?, ?)""",
            (service.lower(), username, nonce, encrypted_password)
        )
        self.conn.commit()

    def get_credential(self, service: str):
        self.cursor.execute(
            "SELECT username, nonce, encrypted_password FROM credentials WHERE service = ?",
            (service.lower(),)
        )
        return self.cursor.fetchone()

    def close(self):
        self.conn.close()