# import dns.resolver
#
#
# def query_dns(domain, record_type):
#     try:
#         answers = dns.resolver.resolve(domain, record_type)
#         for rdata in answers:
#             print(f"{record_type} Record: {rdata}")
#     except dns.resolver.NoAnswer:
#         print(f"No {record_type} record found for {domain}")
#     except dns.resolver.NXDOMAIN:
#         print(f"Domain {domain} does not exist")
#     except Exception as e:
#         print(f"Error: {e}")
#
#
# # Example Usage
# query_dns("example.com", "A")  # IPv4 Address
# query_dns("example.com", "AAAA")  # IPv6 Address
# query_dns("example.com", "MX")  # Mail Exchange
# query_dns("example.com", "TXT")  # Text Records
# query_dns("example.com", "CNAME")  # Canonical Name
# query_dns("example.com", "NS")  # Name Servers
import os

import dns.resolver
import socket
import requests

# Define the intruder status constant for later use in tagging analysis results
# INTRUDER_STATUS = (
#     ('unsafe', 'Unsafe'),
#     ('safe', 'Safe'),
# )
#
# def query_dns(domain, record_type):
#     """Query a specific DNS record type for a domain."""
#     try:
#         answers = dns.resolver.resolve(domain, record_type)
#         results = [rdata.to_text() for rdata in answers]
#         print(f"{record_type} Records for {domain}: {results}")
#         return results
#     except dns.resolver.NoAnswer:
#         print(f"No {record_type} record found for {domain}")
#     except dns.resolver.NXDOMAIN:
#         print(f"Domain {domain} does not exist")
#     except Exception as e:
#         print(f"Error querying {domain} for {record_type}: {e}")
#     return []
#
# def reverse_lookup(ip):
#     """Perform a reverse DNS lookup on an IP address."""
#     try:
#         host = socket.gethostbyaddr(ip)
#         return host[0]
#     except Exception as e:
#         print(f"Reverse lookup failed for {ip}: {e}")
#     return None
#
# def check_threat_intel(ip, api_key):
#     """Example function to cross-check an IP address against a threat intelligence feed (e.g., VirusTotal)."""
#     url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
#     headers = {'x-apikey': api_key}
#     try:
#         response = requests.get(url, headers=headers)
#         if response.ok:
#             data = response.json()
#             reputation = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#             print(f"Threat intel for {ip}: {reputation}")
#             return reputation
#         else:
#             print(f"VirusTotal API error for {ip}: {response.status_code}")
#     except Exception as e:
#         print(f"Error checking threat intel for {ip}: {e}")
#     return None
#
# # Example usage:
# domain = "badssl.com"
# VIRUSTOTAL_SECRET_KEY = "YOUR KEY"  # Replace with your API key
#
# # Query various record types
# a_records = query_dns(domain, "A")
# query_dns(domain, "AAAA")
# query_dns(domain, "MX")
# query_dns(domain, "TXT")
# cname_records = query_dns(domain, "CNAME")
# query_dns(domain, "NS")
#
# # Check reverse DNS for A records to identify spoofing or unexpected redirections
# for ip in a_records:
#     rev = reverse_lookup(ip)
#     if rev:
#         print(f"Reverse lookup: {ip} resolves to {rev}")
#     else:
#         print(f"Could not resolve reverse lookup for {ip}")
#     # Optionally, cross-check with threat intelligence
#     reputation = check_threat_intel(ip, VIRUSTOTAL_SECRET_KEY)
#     # Here, you could compare the reputation to determine if the IP is 'safe' or 'unsafe'
#     # For example:
#     status = INTRUDER_STATUS[1] if reputation and reputation.get("malicious", 0) == 0 else INTRUDER_STATUS[0]
#     print(f"Status for {ip}: {status[1]}")


VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

def query_dns(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return []

def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        return malicious > 0
    return False

def inspect_url(url):
    domain = url.split('//')[-1].split('/')[0]
    inspection_result = {
        'A_records': query_dns(domain, 'A'),
        'AAAA_records': query_dns(domain, 'AAAA'),
        'MX_records': query_dns(domain, 'MX'),
        'TXT_records': query_dns(domain, 'TXT'),
        'CNAME_records': query_dns(domain, 'CNAME'),
        'NS_records': query_dns(domain, 'NS'),
        'reverse_lookups': {},
        'virustotal_malicious': check_virustotal(domain),
    }
    for ip in inspection_result['A_records']:
        inspection_result['reverse_lookups'][ip] = reverse_lookup(ip)
    return inspection_result
