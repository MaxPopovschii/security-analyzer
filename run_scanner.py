from scanner import SecurityScanner
import argparse
import json

def save_report(report, filename="security_report.json"):
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Web Application Security Scanner')
    parser.add_argument('target', help='Target URL or IP address')
    parser.add_argument('--interface', default='eth0', help='Network interface for packet capture')
    parser.add_argument('--duration', type=int, default=30, help='Packet capture duration in seconds')
    args = parser.parse_args()

    scanner = SecurityScanner()
    print(f"[+] Starting security scan for {args.target}")

    # Run port scan
    print("[+] Performing port scan...")
    port_results = scanner.port_scan(args.target)
    scanner.scan_results['port_scan'] = port_results

    # Check SSL certificate
    print("[+] Checking SSL certificate...")
    ssl_results = scanner.check_ssl_certificate(args.target)
    scanner.scan_results['ssl_check'] = ssl_results

    # Analyze HTTP headers
    print("[+] Analyzing HTTP security headers...")
    url = f"https://{args.target}" if not args.target.startswith('http') else args.target
    header_results = scanner.analyze_http_security_headers(url)
    scanner.scan_results['security_headers'] = header_results

    # Capture packets
    print(f"[+] Capturing network traffic for {args.duration} seconds...")
    packet_results = scanner.packet_capture(args.interface, args.duration)
    scanner.scan_results['packet_analysis'] = packet_results

    # Generate and save report
    print("[+] Generating security report...")
    report = scanner.generate_report()
    save_report(report)
    print("[+] Scan complete! Report saved to security_report.json")

if __name__ == "__main__":
    main()