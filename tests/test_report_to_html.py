
import os
import sys
import pytest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from report_to_html import json_report_to_html

def test_json_report_to_html(tmp_path):
    # Crea un report di esempio
    report = {
        "metadata": {"target": "http://example.com", "scanner_version": "1.0.0"},
        "port_scan": {"ports": {"80": {"state": "open", "service": "http"}}},
        "ssl_check": {"issuer": "Test CA", "expiry": "2026-01-01"},
        "security_headers": {"X-Frame-Options": "DENY"},
        "vulnerability_tests": {"sql_injection": "No vulnerability found"},
        "packet_analysis": {"summary": "No suspicious packets"}
    }
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    with open(json_path, 'w') as f:
        json.dump(report, f)
    # Esegui la conversione
    json_report_to_html(str(json_path), str(html_path))
    # Verifica che il file HTML sia stato creato e contenga dati attesi
    assert os.path.exists(html_path)
    with open(html_path) as f:
        html = f.read()
    assert "Security Scan Report" in html
    assert "example.com" in html
    assert "sql_injection" in html
