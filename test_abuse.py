import requests
from config import ABUSEIPDB_KEY

def check_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_KEY
    }

    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }

    response = requests.get(url, headers = headers, params = params)

    if response.status_code == 200:
        data = response.json()['data']

        print(f"\nAbuseIPDB Results:")
        print(f"IP: {ip_address}")
        print(f"Abuse Confidence: {data['abuseConfidenceScore']}%")
        print(f"Total Reports: {data['totalReports']}")
        print(f"Country: {data.get('countryCode', 'Unknown')}")
        print(f"Last Reported: {data.get('lastReportedAt', 'N/A')}")
    else:
        print(f"Error: {response.status_code}")
        print(f"Message: {response.text}")

# Test with a known malicious IP (Tor exit node)
check_abuseipdb("185.220.101.1")