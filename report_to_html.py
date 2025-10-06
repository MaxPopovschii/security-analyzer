    # Directory Listing
    dir_listing = report.get('directory_listing', {})
    if dir_listing:
        html.append('<div class="section"><h2>Directory Listing Enabled</h2><table>')
        html.append('<tr><th>Directory</th><th>Status</th></tr>')
        for d, info in dir_listing.items():
            status = info.get('status', '')
            html.append(f'<tr><td>{d}</td><td>{status}</td></tr>')
        html.append('</table></div>')
import json
import os
from typing import Any, Dict
from datetime import datetime

def json_report_to_html(json_report_path: str, html_report_path: str) -> None:
    """Convert a JSON security report to a styled HTML report."""
    if not os.path.exists(json_report_path):
        raise FileNotFoundError(f"JSON report not found: {json_report_path}")
    with open(json_report_path, 'r') as f:
        report = json.load(f)

    html = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '<title>Security Scan Report</title>',
        '<style>',
        'body { font-family: Arial, sans-serif; margin: 2em; background: #f8f9fa; }',
        'h1 { color: #2c3e50; }',
        'table { border-collapse: collapse; width: 100%; margin-bottom: 2em; }',
        'th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }',
        'th { background: #e9ecef; }',
        '.section { margin-bottom: 2em; }',
        '.vuln { color: #c0392b; font-weight: bold; }',
        '</style>',
        '</head>',
        '<body>',
        '<h1>Security Scan Report</h1>'
    ]

    # Metadata
    meta = report.get('metadata', {})
    html.append('<div class="section"><h2>Metadata</h2><table>')
    for k, v in meta.items():
        html.append(f'<tr><th>{k}</th><td>{v}</td></tr>')
    html.append('</table></div>')

    # Port Scan
    port_scan = report.get('port_scan', {})
    if port_scan:
        html.append('<div class="section"><h2>Port Scan</h2><table>')
        for port, info in port_scan.get('ports', {}).items():
            html.append(f'<tr><th>Port {port}</th><td>{info}</td></tr>')
        html.append('</table></div>')

    # SSL Check
    ssl = report.get('ssl_check', {})
    if ssl:
        html.append('<div class="section"><h2>SSL Certificate</h2><table>')
        for k, v in ssl.items():
            html.append(f'<tr><th>{k}</th><td>{v}</td></tr>')
        html.append('</table></div>')

    # Security Headers
    headers = report.get('security_headers', {})
    if headers:
        html.append('<div class="section"><h2>Security Headers</h2><table>')
        for k, v in headers.items():
            html.append(f'<tr><th>{k}</th><td>{v}</td></tr>')
        html.append('</table></div>')


    # Sensitive Files
    sensitive = report.get('sensitive_files', {})
    if sensitive:
        html.append('<div class="section"><h2>Sensitive Files Exposed</h2><table>')
        html.append('<tr><th>Path</th><th>Status</th><th>Info</th></tr>')
        for path, info in sensitive.items():
            status = info.get('status', '')
            details = ''
            if info.get('protected'):
                details = 'Protected (401/403)'
            elif 'length' in info:
                details = f"Length: {info['length']} bytes"
            html.append(f'<tr><td>{path}</td><td>{status}</td><td>{details}</td></tr>')
        html.append('</table></div>')

    # Vulnerability Tests
    vulns = report.get('vulnerability_tests', {})
    if vulns:
        html.append('<div class="section"><h2>Vulnerability Tests</h2><table>')
        for test, result in vulns.items():
            html.append(f'<tr><th>{test}</th><td class="vuln">{result}</td></tr>')
        html.append('</table></div>')

    # Packet Analysis
    packet = report.get('packet_analysis', {})
    if packet:
        html.append('<div class="section"><h2>Packet Analysis</h2><pre>')
        html.append(json.dumps(packet, indent=2))
        html.append('</pre></div>')

    html.append('</body></html>')

    with open(html_report_path, 'w') as f:
        f.write('\n'.join(html))
    print(f"HTML report generated: {html_report_path}")
