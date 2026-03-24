"""initialyse la base de donnée"""
import sqlite3
from config import DB_PATH

class database():
    def __init__(self):
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cursor = self.db.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute(
            """CREATE TABLE IF NOT EXISTS alert 
            (id INTEGER PRIMARY KEY,
            alert_type VARCHAR(20),
            src_ip VARCHAR(20),
            severite INT,
            timestamp DATE)"""
        )
        self.db.commit()

    def append_alert(self, alert):
        self.cursor.execute(
            "INSERT INTO alert (alert_type, src_ip, severite, timestamp) VALUES (?, ?, ?, ?)",
            (alert.alert_type.name, alert.src_ip, alert.severite, alert.timestamp)
        )
        self.db.commit()

    def get_all_alert(self):
        self.cursor.execute(
            """
            SELECT *
            FROM alert
            ORDER BY timestamp
            """
        )
        return self.cursor.fetchall()

    def get_alert_by_alert_type(self, alert_type):
        self.cursor.execute(
            """
            SELECT *
            FROM alert
            WHERE alert_type = ?
            """, (alert_type.name,)
        )
        return self.cursor.fetchall()

    def get_alert_by_src_ip(self, src_ip):
        self.cursor.execute(
            """
            SELECT *
            FROM alert
            WHERE src_ip = ?
            """, (src_ip,)
        )
        return self.cursor.fetchall()

    def get_alert_by_severite(self, severite):
        self.cursor.execute(
            """
            SELECT *
            FROM alert
            WHERE severite = ?
            """, (severite,)
        )
        return self.cursor.fetchall()

    def close_connection(self):
        self.db.close()
