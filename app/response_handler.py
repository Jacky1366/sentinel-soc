# app/response_handler.py
"""
Layer: Decision Maker
Purpose: Act on classified threats based on severity level.
Depends on: database.py
Called by: process_log_line() in main.py
"""

"""
e.g input: 
{
    "is_threat": True,
    "attack_type": "brute_force",
    "severity": "high",
    "reason": "Multiple failed SSH login attempts...",
    "source_ip": "192.168.64.7",
    "raw_log": "Failed password for root..."
}
"""

from app.database import store_incident

# Simulated blocklist — IPs that have been "blocked"
blocked_ips = set()

def handle(threat: dict):
    """
    Decide what action to take based on severity.
    Stores every incident to the database.
    """
    if not threat.get("is_threat", False):
        return

    severity = threat["severity"]

    if severity == "high":
        action = "blocked"
        blocked_ips.add(threat["source_ip"])
        print(f"[🚨 HIGH] {threat['attack_type']} from {threat['source_ip']} — IP BLOCKED")
        print(f"    Reason: {threat['reason']}")

    elif severity == "medium":
        action = "alerted"
        print(f"[⚠️ MEDIUM] {threat['attack_type']} from {threat['source_ip']}")
        print(f"    Reason: {threat['reason']}")

    else:
        action = "logged"
        print(f"[ℹ️ LOW] {threat['attack_type']} from {threat['source_ip']}")

    # Store every incident to the database
    store_incident({
        "source_ip": threat["source_ip"],
        "attack_type": threat["attack_type"],
        "severity": severity,
        "raw_log": threat["raw_log"],
        "ai_reason": threat.get("reason", ""),
        "action": action
    })