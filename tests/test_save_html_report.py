import sys
import os
import json
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from run_scanner import ScanRunner

def test_save_html_report(tmp_path):
    with patch('nmap.PortScanner'):
        from run_scanner import ScanRunner
        runner = ScanRunner()
        report = {
            "metadata": {"target": "http://test.local", "scanner_version": "1.0.0"},
            "port_scan": {"ports": {"443": {"state": "open", "service": "https"}}},
            "ssl_check": {"issuer": "Test CA", "expiry": "2026-01-01"},
            "security_headers": {"X-Frame-Options": "DENY"},
            "vulnerability_tests": {"csrf": "No vulnerability found"},
            "packet_analysis": {"summary": "No suspicious packets"}
        }
        html_path = tmp_path / "report.html"
        # Patch print to suppress output
        with patch("builtins.print"):
            runner.save_html_report(report, str(html_path))
        assert os.path.exists(html_path)
        with open(html_path) as f:
            html = f.read()
        assert "Security Scan Report" in html
        assert "test.local" in html
        assert "csrf" in html
