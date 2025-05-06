import nmap
import ssl
import socket
from datetime import datetime
from scapy.all import sniff, TCP, UDP, IP
import requests

class SecurityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.vulnerabilities = []
        self.scan_results = {}
        
    def port_scan(self, target_host):
        """Perform comprehensive port scan"""
        try:
            self.nm.scan(target_host, arguments='-sS -sV -O -A')
            return {
                'ports': self.nm[target_host]['tcp'],
                'os': self.nm[target_host].get('osmatch', []),
                'hostname': self.nm[target_host].get('hostname', '')
            }
        except Exception as e:
            return {'error': str(e)}

    def check_ssl_certificate(self, domain, port=443):
        """Validate SSL certificate"""
        try:
            context = ssl.create_default_context()
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable older protocols
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((domain, port)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter'],
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version']
                    }
        except Exception as e:
            return {'error': str(e)}

    def analyze_http_security_headers(self, url):
        """Check security headers"""
        try:
            response = requests.get(url)
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options')
            }
            return security_headers
        except Exception as e:
            return {'error': str(e)}

    def packet_capture(self, interface, duration=30):
        """Capture and analyze network packets"""
        packets = sniff(iface=interface, timeout=duration)
        analysis = {
            'total_packets': len(packets),
            'protocols': {},
            'suspicious_patterns': []
        }
        
        for packet in packets:
            if TCP in packet:
                proto = 'TCP'
            elif UDP in packet:
                proto = 'UDP'
            else:
                proto = 'Other'
                
            analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1
            
            # Check for potential security issues
            if TCP in packet and packet[TCP].flags & 0x02:  # SYN packets
                analysis['suspicious_patterns'].append({
                    'type': 'Potential Port Scan',
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
        
        return analysis

    def test_sql_injection(self, url):
        """Test for SQL Injection vulnerability"""
        try:
            payloads = ["' OR 1=1 --", "' UNION SELECT NULL, NULL --", "'; DROP TABLE users --"]
            for payload in payloads:
                response = requests.get(url + payload)
                if response.status_code == 200 and 'error' in response.text:
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'payload': payload
                    })
                    return True
            return False
        except Exception as e:
            return {'error': str(e)}

    def test_xss(self, url):
        """Test for Cross-Site Scripting (XSS) vulnerability"""
        try:
            payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
            for payload in payloads:
                response = requests.get(url + payload)
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': url,
                        'payload': payload
                    })
                    return True
            return False
        except Exception as e:
            return {'error': str(e)}

    def test_command_injection(self, url):
        """Test for Command Injection vulnerability"""
        try:
            payloads = ["; ls", "| ls", "| whoami"]
            for payload in payloads:
                response = requests.get(url + payload)
                if response.status_code == 200 and "root" in response.text:
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'url': url,
                        'payload': payload
                    })
                    return True
            return False
        except Exception as e:
            return {'error': str(e)}

    def test_csrf(self, url):
        """Test for CSRF vulnerability"""
        try:
            payload = '<img src="' + url + '?action=delete&id=1" />'
            response = requests.get(url + payload)
            if response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'CSRF',
                    'url': url,
                    'payload': payload
                })
                return True
            return False
        except Exception as e:
            return {'error': str(e)}

    def generate_report(self):
        """Generate security analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'scan_results': self.scan_results,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.generate_recommendations()
        }
        return report

    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        # Analyze results and provide recommendations
        for vulnerability in self.vulnerabilities:
            if vulnerability['type'] == 'SQL Injection':
                recommendations.append({
                    'severity': 'High',
                    'description': 'SQL Injection vulnerability found.',
                    'mitigation': 'Use parameterized queries or ORM.'
                })
            elif vulnerability['type'] == 'XSS':
                recommendations.append({
                    'severity': 'High',
                    'description': 'XSS vulnerability found.',
                    'mitigation': 'Sanitize user inputs and use Content Security Policy.'
                })
            elif vulnerability['type'] == 'Command Injection':
                recommendations.append({
                    'severity': 'High',
                    'description': 'Command Injection vulnerability found.',
                    'mitigation': 'Sanitize user inputs and avoid shell commands.'
                })
            elif vulnerability['type'] == 'CSRF':
                recommendations.append({
                    'severity': 'High',
                    'description': 'CSRF vulnerability found.',
                    'mitigation': 'Implement anti-CSRF tokens.'
                })
                
        return recommendations
