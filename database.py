import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scan_logs.db')


class DatabaseManager:
    def __init__(self):
        self.db_path = DB_PATH
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    username  VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role      VARCHAR(20) DEFAULT 'user'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_logs (
                    log_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id   INTEGER,
                    url       TEXT NOT NULL,
                    status    VARCHAR(20) NOT NULL,
                    confidence DECIMAL(5,2),
                    scan_type VARCHAR(20) DEFAULT 'manual',
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_logs(timestamp)'
            )
            conn.commit()

    def insert_log(self, url, status, confidence, user_id=None, scan_type='automatic'):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO scan_logs (user_id, url, status, confidence, scan_type) '
                'VALUES (?, ?, ?, ?, ?)',
                (user_id, url, status, round(float(confidence), 4), scan_type)
            )
            conn.commit()
            return cursor.lastrowid

    def get_logs(self, limit=200, offset=0):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT log_id, user_id, url, status, confidence, scan_type, timestamp '
                'FROM scan_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?',
                (limit, offset)
            )
            return cursor.fetchall()

    def get_stats(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM scan_logs')
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE status='safe'")
            safe = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE status='phishing'")
            phishing = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE status='suspicious'")
            suspicious = cursor.fetchone()[0]
            return {
                'total': total,
                'safe': safe,
                'phishing': phishing,
                'suspicious': suspicious,
            }

    def delete_old_logs(self, days=30):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM scan_logs WHERE timestamp < datetime('now', ?)",
                (f'-{days} days',)
            )
            conn.commit()
            return cursor.rowcount

    def clear_all_logs(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scan_logs')
            conn.commit()
