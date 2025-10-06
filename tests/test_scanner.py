import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner import SecurityScanner


def test_analyze_http_security_headers():
    url = "http://example.com"
    # Mock nmap.PortScanner e requests.get per evitare dipendenze esterne
    with patch('nmap.PortScanner'), patch('requests.get') as mock_get:
        from scanner import SecurityScanner
        scanner = SecurityScanner()
        mock_response = MagicMock()
        mock_response.headers = {
            'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_get.return_value = mock_response
        headers = scanner.analyze_http_security_headers(url)
        assert headers['Strict-Transport-Security'] == 'max-age=63072000; includeSubDomains'
        assert headers['Content-Security-Policy'] == "default-src 'self'"
        assert headers['X-Frame-Options'] == 'DENY'
        assert headers['X-XSS-Protection'] == '1; mode=block'
        assert headers['X-Content-Type-Options'] == 'nosniff'
