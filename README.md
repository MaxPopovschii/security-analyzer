# Security Analyzer

![Pytest](https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square&logo=pytest)

A powerful and automated web application security testing tool designed for vulnerability assessment and penetration testing.

## 🔥 Features

- **Port Scanning**: Comprehensive port and service detection
- **SSL/TLS Analysis**: Certificate validation and security checks
- **Security Headers**: Analysis of HTTP security headers
- **Vulnerability Testing**:
  - SQL Injection detection
  - Cross-Site Scripting (XSS) scanning
  - Command Injection testing
  - CSRF vulnerability checks
- **Network Analysis**: Packet capture and traffic monitoring
- **Detailed Reporting**: JSON-formatted reports with timestamps

## 🚀 Quick Start

### Prerequisites

```bash
# System requirements
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    nmap \
    tcpdump \
    python3-dev \
    libssl-dev

## 🤝 Contributing

Contributi, segnalazioni di bug e suggerimenti sono benvenuti!

1. Fai un fork del repository e crea un branch dedicato per la tua modifica.
2. Assicurati che i test automatici passino eseguendo:

    ```bash
    pip install -r requirements.txt
    pip install pytest
    pytest
    ```

3. Apri una Pull Request descrivendo chiaramente le modifiche.
4. Per segnalare bug o proporre nuove funzionalità, apri una Issue.

Grazie per il tuo contributo!

### Installation

```bash
# Clone the repository
git clone https://github.com/MaxPopovschii/security-analyzer.git
cd security-analyzer

# Install Python dependencies
pip3 install -r requirements.txt
```

## 💻 Usage

### Basic Scan

```bash
sudo python3 run_scanner.py example.com
```

### Advanced Usage

```bash
sudo python3 run_scanner.py example.com \
    --interface eth0 \
    --duration 60 \
    --output custom_report.json \
    --verbose \
    --packet-capture \
    --retries 5 \
    --timeout 45
```

### Available Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target URL/IP | Required |
| `--interface` | Network interface | eth0 |
| `--duration` | Packet capture time | 30s |
| `--output` | Report filename | security_report.json |
| `--verbose` | Detailed output | False |
| `--packet-capture` | Enable packet capture | False |
| `--retries` | Failed test retries | 3 |
| `--timeout` | Request timeout | 30s |

## 📊 Sample Output

```json
{
    "port_scan": {
        "ports": {...},
        "os": [...],
        "hostname": "..."
    },
    "ssl_check": {...},
    "security_headers": {...},
    "vulnerability_tests": {
        "sql_injection": {...},
        "xss": {...},
        "command_injection": {...},
        "csrf": {...}
    }
}
```

## 🛡️ Security Notes

- Only scan systems you own or have explicit permission to test
- Some features require root privileges
- The tool may trigger security alerts
- Follow responsible disclosure practices

## 🔧 Development

### Project Structure

```
security-analyzer/
├── run_scanner.py     # Main execution script
├── scanner.py         # Core scanner implementation
├── requirements.txt   # Python dependencies
├── README.md         # This file
└── security_report.json  # Generated report
```

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚖️ License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only. Users are responsible for compliance with applicable laws and regulations. The authors are not responsible for misuse or damage.

## 🤝 Support

- Report bugs via [Issues](https://github.com/MaxPopovschii/security-analyzer/issues)
- For major changes, please open an issue first to discuss proposed changes

## 🔄 Version History

- 1.0.0: Initial release with core functionality
  - Port scanning
  - Vulnerability testing
  - SSL analysis
  - Network monitoring

---
Created with ❤️ by [MaxPopovschii]