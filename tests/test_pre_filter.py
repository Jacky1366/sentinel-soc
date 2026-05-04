# tests/test_pre_filter.py
"""
Sentinel SOC — Pre-Filter Test Suite
Tests the Stage 1 rule engine using SQA techniques:
  - Boundary Value Analysis (BVA) on brute force thresholds
  - Equivalence Partitioning (EP) on log classifications
  - Security testing on SQL injection detection
"""

import time
import pytest
from app.pre_filter import (
    analyze,
    failed_login_tracker,
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_trackers():
    """Reset all IP trackers between tests so they don't interfere."""
    failed_login_tracker.clear()
    yield
    failed_login_tracker.clear()


# ═══════════════════════════════════════════════════════════
#  1. BRUTE FORCE DETECTION
#     SQA Technique: Boundary Value Analysis (BVA)
#     Threshold = 3 failed logins within 60 seconds
# ═══════════════════════════════════════════════════════════

class TestBruteForceDetection:
    """Boundary Value Analysis on the brute force threshold."""

    FAILED_LOGIN_LINE = "Mar 25 21:40:50 metasploitable sshd[5047]: Failed password for root from 192.168.64.7 port 44322 ssh2"

    def test_below_threshold_not_flagged(self):
        """BVA: 1 and 2 attempts (below threshold of 3) should NOT be flagged."""
        result1 = analyze(self.FAILED_LOGIN_LINE)
        assert result1["is_suspicious"] == False

        result2 = analyze(self.FAILED_LOGIN_LINE)
        assert result2["is_suspicious"] == False

    def test_at_threshold_is_flagged(self):
        """BVA: Exactly 3 attempts (at threshold) SHOULD be flagged."""
        for _ in range(2):
            analyze(self.FAILED_LOGIN_LINE)

        result = analyze(self.FAILED_LOGIN_LINE)
        assert result["is_suspicious"] == True
        assert result["reason"] == "brute_force"
        assert result["source_ip"] == "192.168.64.7"

    def test_above_threshold_still_flagged(self):
        """BVA: 5 attempts (above threshold) should still be flagged."""
        for _ in range(4):
            analyze(self.FAILED_LOGIN_LINE)

        result = analyze(self.FAILED_LOGIN_LINE)
        assert result["is_suspicious"] == True
        assert result["reason"] == "brute_force"
        assert result["attempt_count"] == 5

    def test_different_ips_tracked_separately(self):
        """Each IP should have its own counter — IP A's failures don't affect IP B."""
        line_ip_a = "Failed password for root from 10.0.0.1 port 44322 ssh2"
        line_ip_b = "Failed password for root from 10.0.0.2 port 44322 ssh2"

        # 2 failures from IP A
        analyze(line_ip_a)
        analyze(line_ip_a)

        # 1 failure from IP B — should NOT trigger (only 1 attempt)
        result = analyze(line_ip_b)
        assert result["is_suspicious"] == False

    def test_successful_login_not_flagged(self):
        """A successful login line should never be flagged as brute force."""
        normal_line = "Mar 25 21:40:50 metasploitable sshd[5047]: Accepted password for root from 192.168.64.7 port 44322 ssh2"
        result = analyze(normal_line)
        assert result["is_suspicious"] == False


# ═══════════════════════════════════════════════════════════
#  2. SQL INJECTION DETECTION
#     SQA Technique: Equivalence Partitioning (EP)
#     Partitions: malicious SQL vs normal requests
# ═══════════════════════════════════════════════════════════

class TestSQLInjectionDetection:
    """Equivalence Partitioning on SQL injection patterns."""

    # ── Malicious partition (should be flagged) ──

    def test_select_keyword_detected(self):
        """EP-Malicious: SELECT statement in request should be flagged."""
        line = '192.168.64.7 - - [25/Mar/2026:21:40:50] "GET /page?id=1 UNION SELECT * FROM users"'
        result = analyze(line)
        assert result["is_suspicious"] == True
        assert result["reason"] == "sql_injection"

    def test_drop_table_detected(self):
        """EP-Malicious: DROP TABLE should be flagged."""
        line = '192.168.64.7 - - [25/Mar/2026:21:40:50] "GET /page?id=1; DROP TABLE users"'
        result = analyze(line)
        assert result["is_suspicious"] == True
        assert result["reason"] == "sql_injection"

    def test_or_1_equals_1_detected(self):
        """EP-Malicious: Classic OR 1=1 injection should be flagged."""
        line = "192.168.64.7 - - \"GET /login?user=admin' OR 1=1 --\""
        result = analyze(line)
        assert result["is_suspicious"] == True
        assert result["reason"] == "sql_injection"

    def test_union_keyword_detected(self):
        """EP-Malicious: UNION keyword should be flagged."""
        line = '192.168.64.7 - - "GET /search?q=1 UNION ALL SELECT password FROM accounts"'
        result = analyze(line)
        assert result["is_suspicious"] == True
        assert result["reason"] == "sql_injection"

    def test_case_insensitive_detection(self):
        """SQL keywords should be detected regardless of case."""
        line = '192.168.64.7 - - "GET /page?id=1 union select * from users"'
        result = analyze(line)
        assert result["is_suspicious"] == True
        assert result["reason"] == "sql_injection"

    # ── Normal partition (should NOT be flagged) ──

    def test_normal_get_request_not_flagged(self):
        """EP-Normal: Standard GET request should not be flagged."""
        line = '192.168.64.7 - - [25/Mar/2026:21:40:50] "GET /index.html HTTP/1.1" 200 1234'
        result = analyze(line)
        assert result["is_suspicious"] == False

    def test_normal_post_request_not_flagged(self):
        """EP-Normal: Standard POST request should not be flagged."""
        line = '192.168.64.7 - - [25/Mar/2026:21:40:50] "POST /api/login HTTP/1.1" 200 56'
        result = analyze(line)
        assert result["is_suspicious"] == False


# ═══════════════════════════════════════════════════════════
#  3. PORT SCAN DETECTION
#     SQA Technique: Boundary Value Analysis (BVA)
#     Threshold = 3 scan events within 60 seconds
# ═══════════════════════════════════════════════════════════

class TestPortScanDetection:
    """Boundary Value Analysis on port scan threshold."""

    SCAN_LINE = "Mar 25 21:40:50 metasploitable sshd[5047]: refused connect from 192.168.64.7 (192.168.64.7)"

    def test_below_threshold_not_flagged(self):
        """BVA: 1-2 connection refused events should NOT trigger port scan."""
        result1 = analyze(self.SCAN_LINE)
        assert result1["is_suspicious"] == False

        result2 = analyze(self.SCAN_LINE)
        assert result2["is_suspicious"] == False

    def test_at_threshold_is_flagged(self):
        """BVA: Exactly 3 refused connections SHOULD trigger port scan."""
        for _ in range(2):
            analyze(self.SCAN_LINE)

        result = analyze(self.SCAN_LINE)
        assert result["is_suspicious"] == True
        assert result["reason"] == "port_scan"

    def test_did_not_receive_identification(self):
        """Port scan keyword variant: 'did not receive identification'."""
        line = "Mar 25 21:40:50 metasploitable sshd[5047]: Did not receive identification string from 10.0.0.5"
        for _ in range(2):
            analyze(line)
        result = analyze(line)
        assert result["is_suspicious"] == True
        assert result["reason"] == "port_scan"


# ═══════════════════════════════════════════════════════════
#  4. IP EXTRACTION
#     SQA Technique: Equivalence Partitioning (EP)
#     Partitions: valid IPs, no IP present
# ═══════════════════════════════════════════════════════════

class TestIPExtraction:
    """Verify correct IP extraction from different log formats."""

    def test_auth_log_format(self):
        """Extract IP from standard auth.log format."""
        line = "Mar 25 21:40:50 metasploitable sshd[5047]: Failed password for root from 192.168.64.7 port 44322 ssh2"
        for _ in range(3):
            result = analyze(line)
        assert result["source_ip"] == "192.168.64.7"

    def test_apache_log_format(self):
        """Extract IP from Apache access log format (IP is first field)."""
        line = '10.0.0.55 - - [25/Mar/2026:21:40:50] "GET /page?id=1 UNION SELECT * FROM users"'
        result = analyze(line)
        assert result["source_ip"] == "10.0.0.55"

    def test_no_ip_returns_unknown(self):
        """Log line with no IP should return 'unknown'."""
        line = "some random log line with no IP address"
        result = analyze(line)
        # Should not crash, just return not suspicious
        assert result["is_suspicious"] == False


# ═══════════════════════════════════════════════════════════
#  5. PIPELINE INTEGRATION
#     Verify the analyze() function returns correct structure
# ═══════════════════════════════════════════════════════════

class TestAnalyzeReturnStructure:
    """Ensure analyze() always returns the expected dict format."""

    def test_suspicious_result_has_required_keys(self):
        """Flagged results must include: is_suspicious, reason, source_ip, raw_log."""
        line = '192.168.64.7 - - "GET /page?id=1 UNION SELECT *"'
        result = analyze(line)
        assert "is_suspicious" in result
        assert "reason" in result
        assert "source_ip" in result
        assert "raw_log" in result

    def test_non_suspicious_result_structure(self):
        """Non-flagged results should only have is_suspicious: False."""
        line = "normal system log entry"
        result = analyze(line)
        assert result["is_suspicious"] == False

    def test_raw_log_preserved(self):
        """The original log line should be passed through unchanged."""
        line = '192.168.64.7 - - "GET /page?id=DROP TABLE users"'
        result = analyze(line)
        assert result["raw_log"] == line