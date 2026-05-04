# app/pre_filter.py
"""
Layer: Gatekeeper
Purpose: Fast, free, rule-based triage on every incoming log line.
Depends on: nothing
Called by: process_log_line() in main.py
"""

import re
import time
from collections import defaultdict

# ── Brute Force Tracking ──────────────────────────────────
FAILED_LOGIN_THRESHOLD = 3    # how many failures before flagging
FAILED_LOGIN_WINDOW = 60      # within how many seconds

failed_login_tracker = defaultdict(list)
# failed_login_tracker structure: { "192.168.64.7": [1711234567.1, 1711234567.3, ...] }
# Each IP maps to a list of timestamps when failed logins occurred

# ── SQL Injection Patterns ────────────────────────────────
SQL_PATTERNS = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR\s+1\s*=\s*1|--)",
    re.IGNORECASE # ignore case sensitivity
)

# ── Detection Functions ───────────────────────────────────

def _check_brute_force(line: str, source_ip: str) -> bool:
    """Track failed login frequency per IP."""
    if "Failed password" not in line:
        return False
    now = time.time()
    timestamps = failed_login_tracker[source_ip]
    timestamps.append(now)
    # timestamps == values of the failed_login_tracker dictionary
    # timestamps structure:[1711234560, 1711234565], same as: failed_login_tracker["192.168.64.7"]

    # Remove timestamps outside the window
    failed_login_tracker[source_ip] = [
        t for t in timestamps if now - t <= FAILED_LOGIN_WINDOW
    ]

    return len(failed_login_tracker[source_ip]) >= FAILED_LOGIN_THRESHOLD


def _check_sql_injection(line: str) -> bool:
    """Look for SQL keywords in the log line."""
    return bool(SQL_PATTERNS.search(line))


def _check_port_scan(line: str, source_ip: str) -> bool:
    """Detect connection patterns indicating port probing."""
    scan_keywords = [
        "refused",
        "connection closed",
        "connection reset",
        "illegal port",
        "did not receive identification",
        "transport endpoint is not connected"
    ]
    if not any(kw in line.lower() for kw in scan_keywords):
        return False

    now = time.time()
    key = f"scan_{source_ip}"
    timestamps = failed_login_tracker[key]
    timestamps.append(now)
    failed_login_tracker[key] = [
        t for t in timestamps if now - t <= FAILED_LOGIN_WINDOW
    ]
    return len(failed_login_tracker[key]) >= FAILED_LOGIN_THRESHOLD


# ── IP Extraction ─────────────────────────────────────────
IP_PATTERN = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
# IP_PATTERN = __.__.__.__, e.g. 192.168.64.7

def _extract_ip(line: str) -> str:
    """Pull the first IP address from a log line."""
    match = IP_PATTERN.search(line)
    # match = something like: <re.Match object; span=(35, 47), match='192.168.64.7'>
    return match.group() if match else "unknown" 
    # e.g return "192.168.64.7"


# ── Public API ────────────────────────────────────────────

def analyze(line: str) -> dict:
    """
    Analyze one raw log line.
    Returns a dict with is_suspicious, reason, source_ip, raw_log.
    """
    source_ip = _extract_ip(line)

    if _check_brute_force(line, source_ip):
        count = len(failed_login_tracker[source_ip])   
        return {
            "is_suspicious": True,
            "reason": "brute_force",
            "attempt_count": count,
            "source_ip": source_ip,
            "raw_log": line
        }

    if _check_sql_injection(line):
        return {
            "is_suspicious": True,
            "reason": "sql_injection",
            "source_ip": source_ip,
            "raw_log": line
        }

    if _check_port_scan(line, source_ip):
        count = len(failed_login_tracker[f"scan_{source_ip}"])
        return {
            "is_suspicious": True,
            "reason": "port_scan",
            "attempt_count": count,
            "source_ip": source_ip,
            "raw_log": line
        }

    return {"is_suspicious": False}