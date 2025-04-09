import os
import dns.resolver
import socket
import requests
import hashlib

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

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

def check_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        return response.json()
    return {}

# ip_info
def check_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        return response.json()
    return {}

# url_hash_info
def check_virustotal_url_hash(url):
    url_id = hashlib.sha256(url.encode()).hexdigest()
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(url, headers=VT_HEADERS)
    if response.status_code == 200:
        return response.json()
    return {}

# file_hash
def check_virustotal_uploaded_file(file_obj):
    try:

        file_bytes = file_obj.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()


        vt_file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(vt_file_url, headers=VT_HEADERS)

        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            status = 'unsafe' if malicious_count > 0 else 'safe'
            return {
                "source": "hash_lookup",
                "status": status,
                "data": data
            }
        elif response.status_code == 404:
            file_obj.seek(0)  # rewind file pointer
            files = {'file': (file_obj.name, file_obj, file_obj.content_type)}
            upload_url = "https://www.virustotal.com/api/v3/files"
            upload_response = requests.post(upload_url, files=files, headers=VT_HEADERS)

            if upload_response.status_code == 200:
                upload_data = upload_response.json()
                return {
                    "source": "uploaded",
                    "status": "intruded",
                    "message": "File uploaded for scanning. No results yet.",
                    "data": upload_data
                }
            else:
                return {
                    "status": "intruded",
                    "error": f"Upload failed: {upload_response.status_code}",
                    "details": upload_response.text
                }
        else:
            return {
                "status": "intruded",
                "error": f"File hash lookup failed: {response.status_code}"
            }
    except Exception as e:
        return {"error": str(e)}

# def check_virustotal_file(url):
#     try:
#         response = requests.get(url, timeout=5)
#         if response.ok:
#             file_hash = hashlib.sha256(response.content).hexdigest()
#             vt_file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
#             file_response = requests.get(vt_file_url, headers=VT_HEADERS)
#             if file_response.status_code == 200:
#                 return file_response.json()
#             else:
#                 return {"error": f"File hash lookup failed: {file_response.status_code}"}
#         else:
#             return {"error": f"File not downloadable: {response.status_code}"}
#     except Exception as e:
#         return {"error": str(e)}

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
        'virustotal': {
            'domain_info': check_virustotal_domain(domain),
            'url_hash_info': check_virustotal_url_hash(url),
            'ip_info': {},
        }
    }
    for ip in inspection_result['A_records']:
        inspection_result['reverse_lookups'][ip] = reverse_lookup(ip)
        vt_ip_data = check_virustotal_ip(ip)
        inspection_result['virustotal']['ip_info'][ip] = vt_ip_data
    return inspection_result
