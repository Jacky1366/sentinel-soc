# app/detector.py
"""
Layer: AI Analyst
Purpose: Send flagged logs to OpenAI for deep threat classification.
Depends on: OpenAI API, dotenv
Called by: process_log_line() in main.py
"""
import json
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are a security analyst at a Security Operations Centre.
Analyze the following log entry and respond ONLY with a JSON object.
Do not include any other text, markdown, or explanation outside the JSON.
{
    "is_threat": true or false,
    "attack_type": "brute_force" | "sql_injection" | "port_scan" | "normal",
    "severity": "low" | "medium" | "high",
    "reason": "Brief explanation of your analysis"
}

Severity guidelines:
- high: 8+ failed attempts, active exploitation, clear malicious intent
- medium: 3-7 failed attempts, suspicious but unconfirmed
- low: 1-2 attempts, reconnaissance, low confidence"""


def classify(pre_filter_result: dict) -> dict:
    """
    Send a flagged log to OpenAI for threat classification.
    Falls back to pre-filter's guess if API fails.
    """
    raw_log = pre_filter_result["raw_log"]
    source_ip = pre_filter_result["source_ip"]
    reason = pre_filter_result.get("reason", "suspicious activity")
    attempt_count = pre_filter_result.get("attempt_count", 1)

    # Build context message based on attack type
    if reason == "brute_force":
        context = f"Context: This IP ({source_ip}) has made {attempt_count} failed login attempts in the last 60 seconds."
    elif reason == "port_scan":
        context = f"Context: This IP ({source_ip}) has triggered {attempt_count} port probe/connection events in the last 60 seconds, consistent with a port scan."
    elif reason == "sql_injection":
        context = f"Context: This request contains SQL keywords in the URL or body, suggesting a SQL injection attempt."
    else:
        context = f"Context: Flagged as suspicious by pre-filter. Reason: {reason}"

    user_content = f"Log entry: {raw_log}\n\n{context}"

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content}
            ],
            temperature=0
        )

        result = json.loads(response.choices[0].message.content)

        # Carry forward source_ip and raw_log for the database
        result["source_ip"] = source_ip
        result["raw_log"] = raw_log

        return result

    except Exception as e:
        print(f"[DETECTOR] OpenAI API error: {e}")
        return {
            "is_threat": True,
            "attack_type": reason,
            "severity": "medium",
            "reason": "API unavailable — used pre-filter classification",
            "source_ip": source_ip,
            "raw_log": raw_log
        }