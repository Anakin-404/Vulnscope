import json
import os
import sqlite3
import tempfile
from datetime import datetime

DB_PATH = os.environ.get("VULNSCOPE_DB_PATH")
if not DB_PATH:
    if os.environ.get("VERCEL"):
        DB_PATH = os.path.join(tempfile.gettempdir(), "vulnscope.db")
    else:
        DB_PATH = "vulnscope.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            cve_count INTEGER NOT NULL,
            highest_severity TEXT NOT NULL,
            cves_json TEXT NOT NULL
        )
        """)
        conn.commit()

def save_scan(results):
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    with sqlite3.connect(DB_PATH) as conn:
        for item in results:
            cves = item.get("cves", [])
            highest = max(
                (c.get("severity", "UNKNOWN") for c in cves),
                key=lambda x: rank.get(x, 0),
                default="—"
            )
            conn.execute(
                "INSERT INTO scans (scanned_at, product, version, cve_count, highest_severity, cves_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    item["product"],
                    item["version"],
                    len(cves),
                    highest,
                    json.dumps(cves)
                )
            )
        conn.commit()

def get_history(limit=20):
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("""
            SELECT scanned_at, product, version, cve_count, highest_severity
            FROM scans ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

    return [
        {
            "Scanned At": r[0],
            "Software": r[1],
            "Version": r[2],
            "CVEs": r[3],
            "Highest Severity": r[4]
        }
        for r in rows
    ]
