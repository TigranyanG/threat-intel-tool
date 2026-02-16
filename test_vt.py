import requests
from config import VT_API_KEY

def check_ip(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']

        print(f"IP: {ip_address}")
        print(f"Malicious vendors: {stats['malicious']}")
        print(f"Suspicious vendors: {stats['suspicious']}")
        print(f"Clean vendors: {stats['harmless']}")
    else:
        print(f"Error: {response.status_code}")
        print(f"Message: {response.text}")

# Test with a known malicious IP (Tor exit node)
check_ip("185.220.101.1")