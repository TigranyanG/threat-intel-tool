# Threat Intelligence Enrichment Tool

A command-line tool for automating IP reputation analysis by querying multiple threat intelligence sources simultaneously.

## Features

- **Multi-Source Intelligence**: Queries 5 complementary data sources in parallel
  - VirusTotal - Reputation across 60+ security vendors
  - AbuseIPDB - Abuse confidence and report history
  - GreyNoise - Internet noise classification and RIOT detection
  - ARIN WHOIS - IP registration and ownership data
  - ip-api.com - Geolocation and ISP information

- **Intelligent Risk Assessment**: Automated HIGH/MEDIUM/LOW classification
- **Bulk Processing**: Process multiple IPs from file with rate limiting
- **Graceful Error Handling**: Continues operation even if individual sources fail
- **Professional Output**: Formatted reports with visual risk indicators (🔴🟡🟢)

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

**Required API Keys (Free):**
- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **GreyNoise**: https://www.greynoise.io/ (Community tier)

**No API Key Needed:**
- ARIN WHOIS (public service)
- ip-api.com (45,000 requests/month free)

Add your keys to `config.py`:
```python
VT_API_KEY = "your_virustotal_key_here"
ABUSEIPDB_KEY = "your_abuseipdb_key_here"
GREYNOISE_KEY = "your_greynoise_key_here"
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

**File format** (one IP per line):
```
8.8.8.8
1.1.1.1
185.220.101.1
```

## Example Output
```
======================================================================
                    THREAT INTELLIGENCE REPORT
======================================================================
Generated: 2026-02-16 16:24:09
======================================================================

--- VirusTotal ---
IP Address: 185.220.101.1
Malicious Detections: 14
Suspicious Detections: 3
Clean Detections: 48
Risk Assessment: 🔴 HIGH

--- AbuseIPDB ---
IP Address: 185.220.101.1
Abuse Confidence Score: 100%
Total Reports: 177
Country: DE
ISP: Artikel10 e.V.
Risk Assessment: 🔴 HIGH

--- GreyNoise ---
IP Address: 185.220.101.1
Internet Noise: YES (Mass Scanner)
RIOT (Benign Service): NO
Classification: MALICIOUS
Name: unknown
Risk Assessment: 🔴 HIGH

--- ARIN WHOIS ---
IP Address: 185.220.101.1
Organization: RIPE Network Coordination Centre
Network Range: 185.0.0.0
Registration Date: 2011-01-04T00:00:00-05:00

--- Geolocation ---
IP Address: 185.220.101.1
Country: Germany
City: Brandenburg
ISP: Stiftung Erneuerbare Freiheit
Organization: Artikel10 e.V
Timezone: Europe/Berlin
======================================================================
```

## Use Cases

- **Phishing Investigation**: Quickly assess sender IP reputation
- **Incident Response**: Triage alerts by distinguishing targeted threats from internet noise
- **IOC Validation**: Verify indicators of compromise across multiple sources
- **Threat Hunting**: Correlate IP activity with geolocation and ownership data
- **Security Monitoring**: Bulk-check suspicious IPs from logs or SIEM alerts

## Technical Details

- **Rate Limiting**: Built-in delays between API calls to respect free tier limits
- **Error Resilience**: Continues processing if individual sources fail
- **Data Correlation**: Combines reputation, triage, ownership, and location intelligence
- **Multi-Source Validation**: Cross-references findings across independent threat feeds

## Author

Grisha Tigranyan  
[LinkedIn](https://linkedin.com/in/grisha-tigranyan/) | [GitHub](https://github.com/TigranyanG)

## License

MIT License