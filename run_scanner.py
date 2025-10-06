from scanner import SecurityScanner
import argparse
import json
import logging
import sys
from typing import Dict, Any
from datetime import datetime
from tqdm import tqdm
import time
import requests
from urllib.parse import urlparse
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ScanRunner:
            # Directory listing scan
            self.results['directory_listing'] = self.run_scan_module(
                "Directory Listing Scan",
                self.scanner.check_directory_listing,
                url
            )
    def __init__(self):
        self.scanner = SecurityScanner()
        self.results: Dict[str, Any] = {}
        self._setup_session()
        
    def _setup_session(self):
        """Configure requests session with proper headers and timeout"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        self.session.timeout = 30
        
    def validate_target(self, target: str) -> str:
        """Validate and format target URL"""
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        try:
            # Parse URL properly
            parsed = urlparse(target)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
                
            # Test connection without following redirects
            response = requests.head(
                target, 
                timeout=5, 
                allow_redirects=False,
                verify=False  # Allow self-signed certificates
            )
            
            # Handle redirects manually
            if response.status_code in (301, 302) and 'Location' in response.headers:
                return response.headers['Location']
            return target
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not validate {target}: {str(e)}")
            return target
        except ValueError as e:
            logger.error(f"Invalid target URL: {str(e)}")
            raise

    def save_report(self, report: Dict[str, Any], filename: str = "security_report.json") -> None:
        """Save scan results to a JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Report saved successfully to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
            raise

    def save_html_report(self, report: Dict[str, Any], filename: str = "security_report.html") -> None:
        """Save scan results to an HTML file using the report_to_html module"""
        try:
            from report_to_html import json_report_to_html
            # Save to a temporary JSON file first
            tmp_json = "_tmp_report.json"
            with open(tmp_json, 'w') as f:
                json.dump(report, f, indent=4)
            json_report_to_html(tmp_json, filename)
            os.remove(tmp_json)
            logger.info(f"HTML report saved successfully to {filename}")
        except Exception as e:
            logger.error(f"Failed to save HTML report: {str(e)}")
            raise

    def run_scan_module(self, name: str, func, *args, retries=3, **kwargs) -> Any:
        """Run a scan module with progress tracking, retries and error handling"""
        for attempt in range(retries):
            try:
                logger.info(f"Starting {name} (attempt {attempt + 1}/{retries})")
                with tqdm(total=100, desc=f"Running {name}", ncols=100) as pbar:
                    pbar.update(10)  # Initial setup
                    
                    # Handle special cases for different scan types
                    if name in ('SQL Injection Test', 'XSS Test', 'Command Injection Test', 'CSRF Test'):
                        # Use proper URL encoding for payloads
                        if 'url' in kwargs:
                            kwargs['url'] = self._prepare_url_for_test(kwargs['url'], name)
                    
                    result = func(*args, **kwargs)
                    pbar.update(80)
                    
                    if isinstance(result, dict) and 'error' in result:
                        raise Exception(result['error'])
                        
                    pbar.update(10)
                    logger.info(f"Completed {name}")
                    return result
                    
            except Exception as e:
                logger.error(f"Error in {name} (attempt {attempt + 1}): {str(e)}")
                if attempt == retries - 1:
                    return {"error": str(e)}
                time.sleep(2)

    def _prepare_url_for_test(self, url: str, test_type: str) -> str:
        """Prepare URL for specific test types"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if test_type == 'SQL Injection Test':
            return base_url  # Don't modify the base URL for SQL injection
        elif test_type == 'XSS Test':
            return base_url  # Don't modify the base URL for XSS
        elif test_type == 'Command Injection Test':
            return base_url  # Don't modify the base URL for command injection
        return url

    def scan_target(self, args: argparse.Namespace) -> Dict[str, Any]:
        """Execute all scanning modules with enhanced error handling"""
        start_time = datetime.now()
        
        # Validate and format target URL
        url = self.validate_target(args.target)
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        try:
            # Basic scans
            self.results['port_scan'] = self.run_scan_module(
                "Port Scan", 
                self.scanner.port_scan, 
                hostname
            )

            self.results['ssl_check'] = self.run_scan_module(
                "SSL Certificate Check", 
                self.scanner.check_ssl_certificate, 
                hostname
            )


            self.results['security_headers'] = self.run_scan_module(
                "Security Headers Analysis",
                self.scanner.analyze_http_security_headers,
                url
            )

            # Sensitive files scan (custom list support)
            custom_sensitive = None
            if getattr(args, 'sensitive_list', None):
                try:
                    with open(args.sensitive_list) as f:
                        custom_sensitive = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                except Exception as e:
                    logger.warning(f"Could not read sensitive list file: {e}")
            self.results['sensitive_files'] = self.run_scan_module(
                "Sensitive Files Scan",
                self.scanner.check_sensitive_files,
                url,
                custom_paths=custom_sensitive
            )

            # Vulnerability tests with proper URL handling
            vulnerabilities = {
                'sql_injection': self.run_scan_module(
                    "SQL Injection Test", 
                    self.scanner.test_sql_injection, 
                    url,
                    retries=2
                ),
                'xss': self.run_scan_module(
                    "XSS Test", 
                    self.scanner.test_xss, 
                    url,
                    retries=2
                ),
                'command_injection': self.run_scan_module(
                    "Command Injection Test", 
                    self.scanner.test_command_injection, 
                    url,
                    retries=2
                ),
                'csrf': self.run_scan_module(
                    "CSRF Test", 
                    self.scanner.test_csrf, 
                    url,
                    retries=2
                )
            }
            self.results['vulnerability_tests'] = vulnerabilities

            # Network analysis
            if args.packet_capture:
                self.results['packet_analysis'] = self.run_scan_module(
                    "Packet Capture", 
                    self.scanner.packet_capture, 
                    args.interface, 
                    args.duration
                )

            # Add detailed metadata
            self.results['metadata'] = {
                'target': url,
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration': str(datetime.now() - start_time),
                'scanner_version': '1.0.0',
                'command_args': vars(args)
            }

            return self.results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {'error': str(e)}

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Application Security Scanner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('target', help='Target URL or IP address')
    parser.add_argument('--interface', default='eth0', help='Network interface for packet capture')
    parser.add_argument('--duration', type=int, default=30, help='Packet capture duration in seconds')
    parser.add_argument('--output', default='security_report.json', help='Output report filename')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--packet-capture', action='store_true', help='Enable packet capture')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries for failed tests')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for requests in seconds')
    parser.add_argument('--html', action='store_true', help='Generate HTML report in addition to JSON')
    parser.add_argument('--sensitive-list', type=str, default=None, help='Percorso di un file con percorsi sensibili personalizzati da controllare')
    args = parser.parse_args()

    # Configure logging based on verbosity
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scanner.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    try:
        runner = ScanRunner()
        logger.info(f"Starting security scan for {args.target}")
        
        results = runner.scan_target(args)
        if 'error' not in results:
            runner.save_report(results, args.output)
            if getattr(args, 'html', False):
                html_output = args.output.replace('.json', '.html')
                runner.save_html_report(results, html_output)
                logger.info(f"HTML report saved to {html_output}")
            logger.info(f"Scan completed successfully. Report saved to {args.output}")
        else:
            logger.error(f"Scan failed: {results['error']}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
