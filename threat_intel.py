#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Tool
Queries VirusTotal and AbuseIPDB for IP reputation data
"""

import requests
import argparse
import time
from datetime import datetime
from config import VT_API_KEY, ABUSEIPDB_KEY, GREYNOISE_KEY

def check_virustotal(ip_address):
    """Query VirusTotal API for IP reputation"""

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']

            return {
                'source': 'VirusTotal',
                'ip': ip_address,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'status': 'success'
            }
        else:
            return{
                'status': 'error',
                'source': 'VirusTotal',
                'message': f"HTTP {response.status_code}"
            }
    except Exception as e:
        return {
            'status': 'error',
            'source': 'VirusTotal',
            'message': str(e)
        }
            
def check_abuseipdb(ip_address):
    """Query AbuseIPDB for IP reputation"""

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSEIPDB_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['data']

            return {
                'source': 'AbuseIPDB',
                'ip': ip_address,
                'abuse_score': data['abuseConfidenceScore'],
                'total_reports': data['totalReports'],
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'status': 'success'
            }
        else:
            return {
                'status': 'error',
                'source': 'AbuseIPDB',
                'message': f"HTTP {response.status_code}"
            }
        
    except Exception as e:
        return {
            'status': 'error',
            'source': 'AbuseIPDB',
            'message': str(e)
        }

def check_greynoise(ip_address):
    """Query GreyNoise for noise classification"""

    url = f"https://api.greynoise.io/v3/community/{ip_address}"
    headers = {'key': GREYNOISE_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            return {
                'source': 'GreyNoise',
                'ip': ip_address,
                'noise': data.get('noise', False),
                'riot': data.get('riot', False),
                'classification': data.get('classification', 'unknown'),
                'name': data.get('name', 'Unknown'),
                'status': 'success'
            }
        else:
            return {
                'status': 'error',
                'source': 'GreyNoise',
                'message': f"HTTP {response.status_code}"
            }
    
    except Exception as e:
        return {
            'status': 'error',
            'source': 'GreyNoise',
            'message': str(e)
        }

def check_arin_whois(ip_address):
    """Query ARIN WHOIS for IP registration data"""
    url = f"https://whois.arin.net/rest/ip/{ip_address}"
    headers = {'Accept': 'application/json'}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            net = data.get('net', {})
            
            # Handle orgRef - can be dict or missing
            org_ref = net.get('orgRef', {})
            org_name = org_ref.get('@name', 'Unknown') if isinstance(org_ref, dict) else 'Unknown'
            
            # Handle netBlocks - can be dict with netBlock, or list of netBlocks
            net_blocks = net.get('netBlocks', {})
            if isinstance(net_blocks, dict):
                net_block = net_blocks.get('netBlock', {})
                if isinstance(net_block, dict):
                    net_range = net_block.get('startAddress', {}).get('$', 'Unknown')
                elif isinstance(net_block, list):
                    # If it's a list, take the first one
                    net_range = net_block[0].get('startAddress', {}).get('$', 'Unknown') if net_block else 'Unknown'
                else:
                    net_range = 'Unknown'
            else:
                net_range = 'Unknown'
            
            # Handle registration date
            reg_date = net.get('registrationDate', {})
            registration_date = reg_date.get('$', 'Unknown') if isinstance(reg_date, dict) else 'Unknown'
            
            return {
                'source': 'ARIN WHOIS',
                'ip': ip_address,
                'org_name': org_name,
                'net_range': net_range,
                'registration_date': registration_date,
                'status': 'success'
            }
        else:
            return {
                'status': 'error',
                'source': 'ARIN WHOIS',
                'message': f"HTTP {response.status_code}"
            }
    
    except Exception as e:
        return {
            'status': 'error',
            'source': 'ARIN WHOIS',
            'message': str(e)
        }
    
def check_geolocation(ip_address):
    """Query ip-api.com for geolocation data"""

    url = f"http://ip-api.com/json/{ip_address}"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'source': 'Geolocation',
                    'ip': ip_address,
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'status': 'success'
                }
            else:
                return {
                    'status': 'error',
                    'source': 'Geolocation',
                    'message': data.get('message', 'Unknown error')
                }
        else:
            return {
                'status': 'error',
                'source': 'Geolocation',
                'message': f"HTTP {response.status_code}"
            }
    
    except Exception as e:
        return {
            'status': 'error',
            'source': 'Geolocation',
            'message': str(e)
        }
    


def assess_risk(result):
    """Determine risk level based on results"""

    if result['status'] != 'success':
        return 'UNKNOWN'
    
    if 'malicious' in result:
        if result['malicious'] > 5:
            return 'HIGH'
        elif result['malicious'] > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
        
    if 'abuse_score' in result:
        if result['abuse_score'] > 75:
            return 'HIGH'
        elif result['abuse_score'] > 25:
            return 'MEDIUM'
        else:
            return 'LOW'
        
    if 'classification' in result:
        classification = result['classification'].lower()
        if classification == 'malicious':
            return 'HIGH'
        elif classification == 'benign':
            return 'LOW'
        else:
            return 'MEDIUM'
        
    return 'UNKNOWN'

def display_results(results):
    """Print results in a readable format"""
    print("\n" + "="*70)
    print(" " * 20 + "THREAT INTELLIGENCE REPORT")
    print("="*70)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    for result in results:
        risk = assess_risk(result)
        risk_emoji = {
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }

        print(f"\n--- {result['source']} ---")

        if result['status'] == 'success':
            print(f"IP Address: {result['ip']}")
            
            # VirusTotal data
            if 'malicious' in result:
                print(f"Malicious Detections: {result['malicious']}")
                print(f"Suspicious Detections: {result['suspicious']}")
                print(f"Clean Detections: {result['harmless']}")
            
            # AbuseIPDB data
            if 'abuse_score' in result:
                print(f"Abuse Confidence Score: {result['abuse_score']}%")
                print(f"Total Reports: {result['total_reports']}")
                print(f"Country: {result['country']}")
                print(f"ISP: {result['isp']}")
            
            # GreyNoise data
            if 'noise' in result:
                noise_status = "YES (Mass Scanner)" if result['noise'] else "NO (Targeted/Unknown)"
                riot_status = "YES (Known Good)" if result['riot'] else "NO"
                print(f"Internet Noise: {noise_status}")
                print(f"RIOT (Benign Service): {riot_status}")
                print(f"Classification: {result['classification'].upper()}")
                print(f"Name: {result['name']}")
            
            # ARIN WHOIS data
            if 'org_name' in result:
                print(f"Organization: {result['org_name']}")
                print(f"Network Range: {result['net_range']}")
                print(f"Registration Date: {result['registration_date']}")
            
            # Geolocation data
            if 'timezone' in result:
                print(f"Country: {result['country']}")
                print(f"City: {result['city']}")
                print(f"ISP: {result['isp']}")
                print(f"Organization: {result['org']}")
                print(f"Timezone: {result['timezone']}")
            
            if result['source'] in ['VirusTotal', 'AbuseIPDB', 'GreyNoise']:
                print(f"Risk Assessment: {risk_emoji[risk]} {risk}")

        else:
            print(f"Error: {result['message']}")

    print("\n" + "="*70)

def process_single_ip(ip_address):
    """Process a single IP address"""

    print(f"\nAnalyzing IP: {ip_address}")
    print("Querying threat intelligence sources...")
    
    results = []
    
    # Query VirusTotal
    print("  → Checking VirusTotal...")
    results.append(check_virustotal(ip_address))
    time.sleep(1)  # Rate limiting
    
    # Query AbuseIPDB
    print("  → Checking AbuseIPDB...")
    results.append(check_abuseipdb(ip_address))
    time.sleep(1)
    
    # Query GreyNoise
    print("  → Checking GreyNoise...")
    results.append(check_greynoise(ip_address))
    time.sleep(1)
    
    # Query ARIN WHOIS
    print("  → Checking ARIN WHOIS...")
    results.append(check_arin_whois(ip_address))
    time.sleep(1)
    
    # Query Geolocation
    print("  → Checking Geolocation...")
    results.append(check_geolocation(ip_address))
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Enrichment Tool - Query IP reputation',
        epilog='Example: python3 threat_intel.py --ip 8.8.8.8',
        formatter_class=argparse.RawDescriptionHelpFormatter     
    )

    parser.add_argument('--ip', help='Single IP address to check')
    parser.add_argument('--file', help='File containing list of IPs (one per line)')

    args = parser.parse_args()

    if not args.ip and not args.file:
        parser.print_help
        return
    
    results = []

    if args.ip:
        results = process_single_ip(args.ip)
    elif args.file:
        results = process_file(args.file)

    if results:
        display_results(results)

def process_file(filename):
    """Process multiple IPs from a file"""

    try:
        with open(filename,'r') as f:
            ips = [line.strip() for line in f.readlines() if line.strip()]

        print(f"\nProcessing {len(ips)} IPs from {filename}")

        all_results = []

        for i, ip in enumerate(ips, 1):
            print(f"\n[{i}/{len(ips)}] Processing {ip}...")
            results = process_single_ip(ip)
            all_results.extend(results)
            
            # Rate limiting between IPs
            if i < len(ips):
                time.sleep(2)
        
        return all_results
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

if __name__ == "__main__":
    main()