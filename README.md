# CyScanz - Advanced Web Vulnerability Scanner

<p align="center">
  <em>By: Scav-engeR | HURRICANE SQUAD</em>
</p>

```
 ██████╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║╚══███╔╝
██║      ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║  ███╔╝ 
██║       ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║ ███╔╝  
╚██████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║███████╗
 ╚═════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ 
```

CyScanz is a modular penetration testing toolkit for web vulnerability scanning, with specialized scanners for API security, JWT authentication, and cloud misconfigurations.

## 🚀 Features

- **Core Scanner**: Detects XSS, SQLi, open redirects, LFI, RCE
- **API Security Scanner**: Tests endpoints for auth bypass, IDOR, rate limiting
- **JWT Scanner**: Detects algorithm flaws, token forgery vulnerabilities
- **Cloud Scanner**: Finds exposed credentials, storage buckets, SSRF to metadata services
- **Rich Terminal UI**: Color-coded output with progress indicators
- **Detailed Reporting**: JSON reports for integration with other tools

## 📋 Installation

```bash
# Clone repository
git clone https://github.com/scavenger/cyscanz.git
cd cyscanz

# Install dependencies
pip install -r requirements.txt
```

## 🔍 Usage Guide

### Workflow: Complete Assessment

For comprehensive testing:

1. **Initial scan**:
   ```bash
   python scanners/cyscanz.py --url https://example.com --output findings.txt
   ```

2. **API security scan**:
   ```bash
   python scanners/api_scanner.py --input findings.txt
   ```

3. **JWT authentication scan**:
   ```bash
   python scanners/jwt_scanner.py --input findings.txt
   ```

4. **Cloud misconfiguration scan**:
   ```bash
   python scanners/cloud_scanner.py --input findings.txt
   ```

### Core Scanner Options

```bash
python scanners/cyscanz.py [options]

Options:
  --url URL             Target URL to scan
  --input FILE          File with URLs (one per line)
  --output FILE         Results output file (default: output_urls.txt)
  --timeout SEC         Request timeout (default: 15)
  --concurrency NUM     Concurrent requests (default: 5)
  --proxy FILE          Proxy list file
```

### API Scanner Options

```bash
python scanners/api_scanner.py [options]

Options:
  --input FILE          URLs file to scan
  --url URL             Single URL to scan
  --output FILE         Results file (default: api_scan_results.json)
  --timeout SEC         Request timeout (default: 10)
  --concurrency NUM     Concurrent requests (default: 5)
```

### JWT Scanner Options

```bash
python scanners/jwt_scanner.py [options]

Options:
  --input FILE          URLs file to scan
  --url URL             Single URL to scan
  --output FILE         Results file (default: jwt_scan_results.json)
  --timeout SEC         Request timeout (default: 10)
  --concurrency NUM     Concurrent requests (default: 5)
```

### Cloud Scanner Options

```bash
python scanners/cloud_scanner.py [options]

Options:
  --input FILE          URLs file to scan
  --url URL             Single URL to scan
  --output FILE         Results file (default: cloud_scan_results.json)
  --timeout SEC         Request timeout (default: 10)
  --concurrency NUM     Concurrent requests (default: 5)
  --no-verify-ssl       Disable SSL verification
```

## 📊 Understanding Results

Findings are categorized by severity:
- **Critical**: High potential for compromise, immediate action required
- **High**: Serious vulnerability requiring prompt attention
- **Medium**: Security issue that should be addressed
- **Low**: Minor vulnerability with limited impact

Example output structure:
```json
{
  "scan_date": "2025-04-15 04:19:09",
  "vulnerabilities": [
    {
      "url": "https://example.com/api/user",
      "vulnerability": "Missing Authentication",
      "severity": "Critical",
      "description": "Endpoint returns sensitive data without authentication",
      "evidence": "Response contains user information"
    }
  ]
}
```

## 📝 Scanning Tips

1. **Start small** with specific targets to avoid false positives
2. **Use rate limiting** to avoid being blocked
3. **Manually validate** findings before reporting
4. **Always get permission** before scanning systems you don't own

## ⚠️ Disclaimer

This tool is for security professionals to test systems with explicit permission. The developers are not responsible for misuse or damage. Use responsibly.

---

<p align="center">Made with ❤️ by Scav-engeR | Monsoon Squad</p>
