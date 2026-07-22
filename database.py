import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.getenv("OSAF_DB_PATH", "reports/osaf_history.db")

def init_db():
    """Αρχικοποίηση της βάσης δεδομένων και των πινάκων."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            profile TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            vulnerabilities_count INTEGER,
            full_report TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan_result(target: str, profile: str, vulnerabilities_count: int, report_data: dict):
    """Αποθήκευση αποτελέσματος σάρωσης στη βάση δεδομένων."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_history (target, profile, timestamp, vulnerabilities_count, full_report)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        target,
        profile,
        datetime.now().isoformat(),
        vulnerabilities_count,
        json.dumps(report_data)
    ))
    conn.commit()
    conn.close()

def get_recent_scans(limit: int = 5):
    """Ανάκτηση των πιο πρόσφατων σαρώσεων."""
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_history ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]