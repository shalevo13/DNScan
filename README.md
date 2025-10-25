# DNS Vulnerability Scanner - Web Application

A stunning web-based DNS security testing tool that helps you identify potential vulnerabilities in your DNS infrastructure.

## Features

🔍 **Comprehensive DNS Security Testing**
- Zone Transfer (AXFR) vulnerability detection
- SPF and DMARC email authentication checks
- Wildcard DNS configuration analysis
- MX record validation
- CNAME takeover risk assessment
- Nameserver health monitoring

✨ **Beautiful Modern Interface**
- Animated starfield background
- Responsive design for all devices
- Real-time test results with visual indicators
- Color-coded severity levels
- Smooth animations and transitions

📊 **Detailed Analytics**
- Security score calculation
- Test statistics dashboard
- Comprehensive vulnerability reports
- Severity classifications (Critical, High, Medium, Low)

## Installation

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python app.py
   ```

3. **Access the Web Interface**
   - Open your browser and navigate to: `http://localhost:5000`

## Usage

1. **Enter Domain Information**
   - Domain Name: The domain you want to test (e.g., `example.com`)
   - Nameserver IP: The DNS server to query (default: `127.0.0.1`)

2. **Start Scan**
   - Click "Start Security Scan" to begin the analysis

3. **Review Results**
   - View overall security score
   - Check individual test results
   - Review detailed findings for each test

## Test Descriptions

### Zone Transfer (AXFR)
**Severity:** Critical  
Checks if unauthorized zone transfers are allowed. If vulnerable, attackers can retrieve all DNS records.

### SPF Record
**Severity:** Medium  
Verifies the presence of Sender Policy Framework records to prevent email spoofing.

### DMARC Record
**Severity:** Medium  
Checks for Domain-based Message Authentication, Reporting, and Conformance records.

### Wildcard DNS
**Severity:** Low  
Detects wildcard DNS configurations that may be used for phishing attacks.

### MX Records
**Severity:** Medium  
Validates that mail exchanger records point to resolvable hosts.

### CNAME Takeover Risk
**Severity:** High  
Identifies external CNAME targets that could be vulnerable to subdomain takeover.

### Nameserver Health
**Severity:** High  
Ensures all nameservers are properly configured and reachable.

## Original CLI Tool

The original command-line tool is still available in `potential_dns_vuln_tester.py`:

```bash
python potential_dns_vuln_tester.py example.com
```

## Technology Stack

- **Backend:** Flask (Python)
- **DNS Library:** dnspython
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Styling:** Custom CSS with animations
- **Icons:** SVG icons

## Security Note

This tool is designed for legitimate security testing of domains you own or have permission to test. Unauthorized scanning may be illegal in your jurisdiction.

## License

Educational and security research purposes.

## Author

DNS Vulnerability Scanner - 2025
