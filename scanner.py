    def check_sensitive_files(self, url: str, custom_paths=None) -> dict:
        """Check for accessible sensitive files and directories via HTTP. Permette una lista personalizzata."""
        logger.info(f"Checking for sensitive files on {url}")
        default_paths = [
            '.env', '.git/config', 'config.php', 'config.json', 'backup.zip', 'db.sqlite',
            'admin/', 'phpinfo.php', 'test.php', 'debug.log', 'wp-config.php', 'composer.json',
            '.htaccess', '.DS_Store', 'docker-compose.yml', 'package.json',
            # Backup files
            'index.php~', 'index.php.bak', 'index.html~', 'index.html.bak',
            'config.old', 'config.bak', 'wp-config.php~', 'wp-config.php.bak',
            'db.sql', 'db.sql.bak', 'database.sql', 'database.sql.bak',
            'site.zip', 'site.tar.gz', 'backup.tar.gz', 'backup.sql',
            # Private keys
            'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_dsa.pub', 'id_ecdsa', 'id_ecdsa.pub', 'id_ed25519', 'id_ed25519.pub',
            # Log files
            'error.log', 'access.log', 'debug.log', 'server.log', 'application.log',
            # Temporary and swap files
            '.bash_history', '.mysql_history', '.psql_history',
            '.viminfo', '.nfs00000001', '.nfs00000002',
            '.swp', '.swo', '.tmp', '.temp', '.bak', '.old', '.save',
            'core', 'core.dump',
        ]
        sensitive_paths = custom_paths if custom_paths else default_paths
        found = {}
        for path in sensitive_paths:
            test_url = url.rstrip('/') + '/' + path
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and resp.content and len(resp.content) > 0:
                    found[path] = {'status': resp.status_code, 'length': len(resp.content)}
                elif resp.status_code in (401, 403):
                    found[path] = {'status': resp.status_code, 'protected': True}
            except Exception as e:
                logger.debug(f"Error checking {test_url}: {e}")
        return found
import nmap
import ssl
import socket
from datetime import datetime
from scapy.all import sniff, TCP, UDP, IP
import requests
from typing import Dict, List, Any
import logging
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityScanner:

    def check_directory_listing(self, url: str, dirs=None) -> dict:
        """Check if directory listing is enabled for common or custom directories."""
        logger.info(f"Checking for directory listing on {url}")
        default_dirs = ['admin/', 'backup/', 'uploads/', 'files/', 'data/', 'tmp/', 'logs/', 'test/']
        dirs_to_check = dirs if dirs else default_dirs
        found = {}
        for d in dirs_to_check:
            test_url = url.rstrip('/') + '/' + d.lstrip('/')
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and self._looks_like_dir_listing(resp.text):
                    found[d] = {'status': resp.status_code, 'listing': True}
            except Exception as e:
                logger.debug(f"Error checking {test_url}: {e}")
        return found

    def _looks_like_dir_listing(self, html: str) -> bool:
        # Heuristic: look for common directory listing patterns
        patterns = [
            'Index of /',
            '<title>Index of',
            'Parent Directory',
            'Directory listing for',
            'Name\s+Last modified',
        ]
        return any(p in html for p in patterns)
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.scan_results: Dict[str, Any] = {}
        self.session = requests.Session()
        
    def port_scan(self, target_host: str) -> Dict[str, Any]:
        """Perform comprehensive port scan"""
        try:
            logger.info(f"Starting port scan on {target_host}")
            self.nm.scan(target_host, arguments='-sS -sV -O -A')
            return {
                'ports': self.nm[target_host]['tcp'],
                'os': self.nm[target_host].get('osmatch', []),
                'hostname': self.nm[target_host].get('hostname', '')
            }
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {'error': str(e)}

    def check_ssl_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Validate SSL certificate"""
        try:
            logger.info(f"Checking SSL certificate for {domain}")
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
            logger.error(f"SSL certificate check failed: {str(e)}")
            return {'error': str(e)}

    def analyze_http_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers"""
        try:
            logger.info(f"Analyzing HTTP security headers for {url}")
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
            logger.error(f"HTTP security headers analysis failed: {str(e)}")
            return {'error': str(e)}

    def packet_capture(self, interface: str, duration: int = 30) -> Dict[str, Any]:
        """Capture and analyze network packets"""
        try:
            logger.info(f"Starting packet capture on interface {interface} for {duration} seconds")
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
        except Exception as e:
            logger.error(f"Packet capture failed: {str(e)}")
            return {'error': str(e)}

    def test_sql_injection(self, url: str) -> bool:
        """Enhanced SQL Injection testing"""
        try:
            logger.info(f"Testing SQL Injection on {url}")
            payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL--",
                "' OR 1=1#",
                "') OR ('1'='1",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1' UNION SELECT NULL,table_name FROM information_schema.tables--",
                "admin' --",
                "admin' #",
                "' OR 1=1 LIMIT 1--"
            ]
            
            # Test both GET and POST methods
            for payload in payloads:
                # GET request test
                response = self.session.get(url + payload)
                if self._check_sql_error(response.text):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'method': 'GET',
                        'url': url,
                        'payload': payload,
                        'evidence': self._extract_error_message(response.text)
                    })
                    return True
                
                # POST request test
                form_fields = self._get_form_fields(url)
                for field in form_fields:
                    data = {field: payload}
                    response = self.session.post(url, data=data)
                    if self._check_sql_error(response.text):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'method': 'POST',
                            'url': url,
                            'field': field,
                            'payload': payload,
                            'evidence': self._extract_error_message(response.text)
                        })
                        return True
            return False
        except Exception as e:
            logger.error(f"SQL Injection test failed: {str(e)}")
            return {'error': str(e)}

    def test_xss(self, url: str) -> bool:
        """Enhanced XSS testing"""
        try:
            logger.info(f"Testing XSS on {url}")
            payloads = [
                '<script>alert("XSS")</script>',
                '<img src="x" onerror="alert(1)">',
                '<svg/onload=alert(1)>',
                '"><script>alert(1)</script>',
                '" onclick="alert(1)',
                '<IMG SRC=javascript:alert("XSS")>',
                '<svg><script>alert(1)</script></svg>',
                '"><img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<input autofocus onfocus=alert(1)>'
            ]
            
            for payload in payloads:
                # Test GET parameters
                response = self.session.get(url + payload)
                if self._check_xss_reflection(response.text, payload):
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'method': 'GET',
                        'url': url,
                        'payload': payload,
                        'evidence': self._extract_xss_context(response.text, payload)
                    })
                    return True
                
                # Test POST parameters
                forms = self._get_forms(url)
                for form in forms:
                    for field in form.get('fields', []):
                        data = {field: payload}
                        response = self.session.post(url, data=data)
                        if self._check_xss_reflection(response.text, payload):
                            self.vulnerabilities.append({
                                'type': 'XSS',
                                'method': 'POST',
                                'url': url,
                                'form': form['action'],
                                'field': field,
                                'payload': payload,
                                'evidence': self._extract_xss_context(response.text, payload)
                            })
                            return True
            return False
        except Exception as e:
            logger.error(f"XSS test failed: {str(e)}")
            return {'error': str(e)}

    def _check_sql_error(self, content: str) -> bool:
        """Check for SQL error messages"""
        error_patterns = [
            'SQL syntax.*MySQL',
            'Warning.*mysql_.*',
            'MySQL Query fail.*',
            'PostgreSQL.*ERROR',
            'ORA-[0-9][0-9][0-9][0-9]',
            'Microsoft SQL Native Client error',
            'SQLITE_ERROR'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns)

    def _get_forms(self, url: str) -> List[Dict[str, Any]]:
        """Extract forms from page"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            for form in soup.find_all('form'):
                form_info = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'fields': [input.get('name') for input in form.find_all(['input', 'textarea'])]
                }
                forms.append(form_info)
            return forms
        except Exception as e:
            logger.error(f"Form extraction failed: {str(e)}")
            return []

    def _check_xss_reflection(self, content: str, payload: str) -> bool:
        """Check if XSS payload is reflected in response"""
        return payload.lower() in content.lower()

    def analyze_response(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze HTTP response for security issues"""
        analysis = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'cookies': dict(response.cookies),
            'response_size': len(response.content),
            'security_issues': []
        }
        
        # Check for sensitive information disclosure
        if re.search(r'password|passwd|pwd|user|username|email', response.text, re.I):
            analysis['security_issues'].append('Potential sensitive information disclosure')
            
        return analysis

    def test_command_injection(self, url: str) -> bool:
        """Test for Command Injection vulnerability"""
        try:
            logger.info(f"Testing Command Injection on {url}")
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
            logger.error(f"Command Injection test failed: {str(e)}")
            return {'error': str(e)}

    def test_csrf(self, url: str) -> bool:
        """Test for CSRF vulnerability"""
        try:
            logger.info(f"Testing CSRF on {url}")
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
            logger.error(f"CSRF test failed: {str(e)}")
            return {'error': str(e)}

    def generate_report(self) -> Dict[str, Any]:
        """Generate security analysis report"""
        logger.info("Generating security analysis report")
        report = {
            'timestamp': datetime.now().isoformat(),
            'scan_results': self.scan_results,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.generate_recommendations()
        }
        return report

    def generate_recommendations(self) -> List[Dict[str, str]]:
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

    def scan_target(self, target: str, interface: str = 'eth0', duration: int = 30) -> Dict[str, Any]:
        """
        Perform comprehensive security scan
        """
        try:
            logger.info(f"Starting scan on {target}")
            
            # Port scanning
            self.scan_results['port_scan'] = self.port_scan(target)
            
            # SSL check
            self.scan_results['ssl_check'] = self.check_ssl_certificate(target)
            
            # Security headers
            url = f"https://{target}" if not target.startswith('http') else target
            self.scan_results['security_headers'] = self.analyze_http_security_headers(url)
            
            # Vulnerability tests
            self.test_vulnerabilities(url)
            
            # Packet capture
            self.scan_results['packet_analysis'] = self.packet_capture(interface, duration)
            
            return self.generate_report()
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {'error': str(e)}

    def test_vulnerabilities(self, url: str) -> None:
        """
        Run all vulnerability tests
        """
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_command_injection,
            self.test_csrf
        ]
        
        for test in tests:
            try:
                logger.info(f"Running {test.__name__}")
                test(url)
            except Exception as e:
                logger.error(f"Test {test.__name__} failed: {str(e)}")
