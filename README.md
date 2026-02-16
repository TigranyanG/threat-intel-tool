# Threat Intelligence Enrichment Tool

A command-line tool for enriching IP addresses with threat intelligence data from multiple sources.

## Features

- Query VirusTotal for IP reputation
- Query AbuseIPDB for abuse reports
- Automated risk assessment (HIGH/MEDIUM/LOW)
- Bulk IP processing from files
- Professional formatted output with risk indicators

## Installation
```bash
# Clone repository
git clone https://github.com/TigranyanG/threat-intel-tool.git
cd threat-intel-tool

# Install dependencies
pip3 install -r requirements.txt

# Configure API keys
cp config.py.example config.py
# Edit config.py and add your API keys
```

## Configuration

1. Sign up for free API keys:
   - VirusTotal: https://www.virustotal.com/gui/join-us
   - AbuseIPDB: https://www.abuseipdb.com/register

2. Add your keys to `config.py`:
```python
VT_API_KEY = "your_virustotal_key_here"
ABUSEIPDB_KEY = "your_abuseipdb_key_here"
```

## Usage

**Check single IP:**
```bash
python3 threat_intel.py --ip 8.8.8.8
```

**Check multiple IPs from file:**
```bash
python3 threat_intel.py --file ips.txt
```

## Example Output
```
======================================================================
                    THREAT INTELLIGENCE REPORT
======================================================================
Generated: 2026-02-15 23:09:25
======================================================================

--- VirusTotal ---
IP Address: 185.220.101.1
Malicious Detections: 15
Suspicious Detections: 2
Clean Detections: 48
Risk Assessment: 🔴 HIGH

--- AbuseIPDB ---
IP Address: 185.220.101.1
Abuse Confidence Score: 100%
Total Reports: 178
Country: DE
ISP: Artikel10 e.V.
Risk Assessment: 🔴 HIGH
======================================================================
```

## Use Cases

- Phishing investigation
- Incident response
- IOC validation
- Threat hunting
- Security monitoring

## Author

Grisha Tigranyan  
[LinkedIn](https://linkedin.com/in/grisha-tigranyan/) | [GitHub](https://github.com/TigranyanG)

## License

MIT License