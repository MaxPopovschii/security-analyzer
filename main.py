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
            if 'open_ports' in vulnerability:
                recommendations.append({
                    'severity': 'High',
                    'description': f'Close unnecessary ports: {vulnerability["open_ports"]}',
                    'mitigation': 'Configure firewall rules to restrict access'
                })
                
        return recommendations