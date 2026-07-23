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


def get_target_history(target: str, limit: int = 3):
    """Ανάκτηση των πιο πρόσφατων σαρώσεων για ΣΥΓΚΕΚΡΙΜΕΝΟ target (πιο πρόσφατα πρώτα).
    Αποτελεί τη βάση για cross-run 'μνήμη' του agent."""
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, timestamp, profile, vulnerabilities_count, full_report '
        'FROM scan_history WHERE target = ? ORDER BY id DESC LIMIT ?',
        (target, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def summarize_target_memory(target: str, limit: int = 3) -> str:
    """
    Παράγει μια σύντομη, LLM-ready περίληψη προηγούμενων σαρώσεων του ίδιου target,
    ώστε ο agent να έχει πραγματική 'μνήμη' μεταξύ διαφορετικών runs
    (π.χ. να μην ξανασημαίνει ό,τι έχει ήδη καταγραφεί, ή να επισημαίνει
    ευρήματα που επιμένουν σε πολλαπλά scans).
    Επιστρέφει κενό string αν δεν υπάρχει ιστορικό — ο caller πρέπει να το χειριστεί ως 'no memory'.
    """
    history = get_target_history(target, limit=limit)
    if not history:
        return ""

    lines = [f"Previous scan history for target '{target}' ({len(history)} prior run(s), most recent first):"]
    for entry in history:
        vuln_names = []
        try:
            full_report = json.loads(entry.get("full_report") or "{}")
            for v in full_report.get("web_vulnerabilities", [])[:5]:
                name = v.get("name")
                if name:
                    vuln_names.append(str(name))
        except Exception:
            pass

        names_str = ", ".join(vuln_names) if vuln_names else "no named findings recorded"
        lines.append(
            f"- {entry.get('timestamp')} [profile={entry.get('profile')}]: "
            f"{entry.get('vulnerabilities_count')} finding(s) — top findings: {names_str}"
        )

    return "\n".join(lines)