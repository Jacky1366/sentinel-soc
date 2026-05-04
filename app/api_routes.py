"""
api_routes.py — Dashboard API endpoint for Sentinel SOC

Reads from the SQLite incidents database and returns
the JSON structure the frontend dashboard expects.

Add to your main.py:
    from app.api_routes import router as api_router
    app.include_router(api_router)
"""

import sqlite3
import os
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "incidents.db")


def get_db_connection():
    """Open a read-only connection to incidents.db."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/api/incidents")
async def get_incidents():
    """
    Returns all dashboard data in a single response:
    - incidents: full list from DB (newest first)
    - blocked_ips: unique IPs where action = 'blocked'
    - stats: total threats, critical count, blocked count
    - attack_counts: breakdown by attack_type
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # ── Fetch all incidents (newest first) ──
        cursor.execute("""
            SELECT id, timestamp, source_ip, attack_type,
                   severity, raw_log, ai_reason, action
            FROM incidents
            ORDER BY id DESC
        """)
        rows = cursor.fetchall()

        incidents = []
        for row in rows:
            incidents.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "type": row["attack_type"],
                "severity": row["severity"],
                "raw_log": row["raw_log"],
                "reason": row["ai_reason"] or "",
                "action": row["action"]
            })

        # ── Blocked IPs (most recent block entry per IP) ──
        cursor.execute("""
            SELECT i.source_ip, i.attack_type, i.timestamp
            FROM incidents i
            INNER JOIN (
                SELECT source_ip, MAX(id) AS max_id
                FROM incidents
                WHERE action = 'blocked'
                GROUP BY source_ip
            ) latest ON i.id = latest.max_id
            ORDER BY i.id DESC
        """)
        blocked_rows = cursor.fetchall()
        blocked_ips = [
            {
                "ip": r["source_ip"],
                "reason": r["attack_type"],
                "blocked_at": r["timestamp"]
            }
            for r in blocked_rows
        ]

        # ── Stats ──
        total = len(incidents)
        critical = sum(1 for i in incidents if i["severity"] == "high")
        blocked_count = len(blocked_ips)

        # ── Attack type breakdown ──
        attack_counts = {"brute_force": 0, "sql_injection": 0, "port_scan": 0}
        for i in incidents:
            atype = i["type"]
            if atype in attack_counts:
                attack_counts[atype] += 1
            else:
                # Catch any unexpected types
                attack_counts[atype] = attack_counts.get(atype, 0) + 1

        return JSONResponse(content={
            "incidents": incidents,
            "blocked_ips": blocked_ips,
            "stats": {
                "threats": total,
                "critical": critical,
                "blocked": blocked_count
            },
            "attack_counts": attack_counts
        })

    finally:
        conn.close()