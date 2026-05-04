# app/database.py
"""
Layer: Storage
Purpose: SQLite database for persisting security incidents.
Depends on: nothing (foundation layer)
Called by: response_handler.py
"""

import sqlite3
from datetime import datetime, timezone

DB_PATH = "incidents.db" #store the file path in a variable


def init_db():
    """Create the incidents table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            source_ip   TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity    TEXT NOT NULL,
            raw_log     TEXT NOT NULL,
            ai_reason   TEXT,
            action      TEXT NOT NULL
        )
    """)
    conn.commit() # save the changes to disk
    conn.close() # release the connection


def store_incident(incident: dict) -> int: # save the incident to the database(disk) permanently
    """
    Insert one incident record.
    Returns the new row's id.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        INSERT INTO incidents
            (timestamp, source_ip, attack_type, severity, raw_log, ai_reason, action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        incident.get("timestamp", datetime.now(timezone.utc).isoformat()), # if no timestamp, use current time
        incident["source_ip"],
        incident["attack_type"],
        incident["severity"],
        incident["raw_log"],
        incident.get("ai_reason", ""), # if no ai_reason, use empty string
        incident["action"]
    ))
    conn.commit()
    row_id = cursor.lastrowid # get the id of the new row
    conn.close()
    return row_id