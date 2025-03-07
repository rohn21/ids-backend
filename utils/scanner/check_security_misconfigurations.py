import requests, json
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import subprocess
import logging
from celery import shared_task

nikto_path = "/usr/local/bin/nikto"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@shared_task
def run_scan(target_url):
    """Runs a scan and returns structured findings."""
    findings = []

    try:
        command = ['wapiti', '-u', target_url, '-f', 'json', '-o', 'wapiti_results.json']
        result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # output = result.stdout
        output = result.communicate()

        try:
            with open('wapiti_results.json', 'r') as file:
                wapiti_data = json.load(file)

            for vuln in wapiti_data.get("vulnerabilities", []):
                findings.append({
                    "vulnerability_name": vuln.get("name", "Unknown Vulnerability"),
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "description": vuln.get("description", "No description available"),
                    "affected_resource": vuln.get("url", target_url)
                })

        except FileNotFoundError:
            findings.append({
                "vulnerability_name": "Wapiti Scan Error",
                "severity": "LOW",
                "description": "Wapiti results file not found.",
                "affected_resource": target_url
            })

        return findings

    except Exception as e:
        findings.append({
            "vulnerability_name": "Wapiti Scan Error",
            "severity": "LOW",
            "description": str(e),
            "affected_resource": target_url
        })


def check_default_accounts(target_url):
    DEFAULT_CREDENTIALS = [("admin", "admin"), ("root", "root"), ("user", "password")]

    login_paths = ["/admin", "/login", "/user", "/wp-login.php"]
    findings = []

    for path in login_paths:
        url = target_url.rstrip("/") + path
        response = requests.get(url)
        if response.status_code == 200:
            for username, password in DEFAULT_CREDENTIALS:
                login_data = {"username": username, "password": password}
                login_response = requests.post(url, data=login_data)
                if login_response.status_code == 200:
                    findings.append({
                        "vulnerability_name": "Default Account Detected",
                        "severity": "HIGH",
                        "description": f"Login page {url} accepts default credentials {username}:{password}",
                        "affected_resource": url
                    })
    return findings


# def check_default_configs(url):
#     """Check if default accounts or common login pages are exposed."""
#     login_pages = ["/admin", "/login", "/phpmyadmin"]
#     vulnerable_pages = []
#
#     for page in login_pages:
#         response = requests.get(url + page)
#         if response.status_code == 200:
#             vulnerable_pages.append(url + page)
#
#     return [{"vulnerability_name": "Exposed Login Page",
#              "severity": "HIGH",
#              "description": "Login page is accessible and may allow default credentials.",
#              "affected_resource": page}
#             for page in vulnerable_pages]

def check_password_policy(target_url):
    policy_url = target_url.rstrip("/") + "/password-policy"
    response = requests.get(policy_url)
    findings = []

    if response.status_code == 200 and "min_length" in response.json():
        if response.json()["min_length"] < 8:
            findings.append({
                "vulnerability_name": "Weak Password Policy",
                "severity": "MEDIUM",
                "description": "Password policy allows weak passwords.",
                "affected_resource": policy_url
            })
    return findings


# def check_sensitive_files(url):
#     """Check for exposed sensitive files such as .env, config.php, etc."""
#     sensitive_files = [".env", "config.php", ".git/config", "wp-config.php", "robots.txt", "backup.zip"]
#     exposed_files = []
#
#     for file in sensitive_files:
#         url = f"{url.rstrip('/')}/{file}"
#         response = requests.get(url)
#         if response.status_code == 200:
#             exposed_files.append(url + "/" + file)
#
#     return [{"vulnerability_name": "Exposed Sensitive File",
#              "severity": "MEDIUM",
#              "description": f"Sensitive file {file} is publicly accessible.",
#              "affected_resource": file}
#             for file in exposed_files]

def check_unpublished_urls_and_sensitive_files(target_url):
    """
    Checks if sensitive URLs listed in robots.txt and common sensitive files are publicly accessible.
    """
    findings = []

    # Check for unpublished URLs in robots.txt
    robots_url = f"{target_url.rstrip('/')}/robots.txt"
    response = requests.get(robots_url)
    accessible_urls = []

    if response.status_code == 200:
        disallowed_paths = []
        for line in response.text.split("\n"):
            if line.startswith("Disallow:"):
                path = line.split(":")[1].strip()
                disallowed_paths.append(path)

        # Check if these URLs are publicly accessible
        for path in disallowed_paths:
            test_url = f"{target_url.rstrip('/')}{path}"
            page_response = requests.get(test_url)

            if page_response.status_code == 200:
                accessible_urls.append(test_url)

        # Add a single finding if any URLs are publicly accessible
        if accessible_urls:
            findings.append({
                "vulnerability_name": "Unpublished URLs Are Not Blocked",
                "severity": "MEDIUM",
                "description": "The following unpublished URLs are publicly accessible:",
                "affected_resource": accessible_urls
            })

    # Check for exposed sensitive files
    sensitive_files = [".env", "config.php", ".git/config", "wp-config.php", "backup.zip"]
    exposed_files = []

    for file in sensitive_files:
        file_url = f"{target_url.rstrip('/')}/{file}"
        file_response = requests.get(file_url)

        if file_response.status_code == 200:
            exposed_files.append(file_url)

    if exposed_files:
        findings.append({
            "vulnerability_name": "Exposed Sensitive Files",
            "severity": "MEDIUM",
            "description": "The following sensitive files are publicly accessible:",
            "affected_resource": exposed_files
        })

    return findings


def check_security_headers(url):
    """Check for missing security headers in HTTP response."""
    response = requests.get(url)
    headers = response.headers
    missing_headers = []

    required_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]

    for header in required_headers:
        if header not in headers:
            missing_headers.append(header)

    return [{"vulnerability_name": "Missing Security Headers",
             "severity": "LOW",
             "description": f"{header} header is missing.",
             "affected_resource": url}
            for header in missing_headers]


def check_server_info_in_html(target_url):
    response = requests.get(target_url)
    findings = []

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for suspicious comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and "server" in text.lower())

        for comment in comments:
            findings.append({
                "vulnerability_name": "Server Info Leaked in HTML",
                "severity": "MEDIUM",
                "description": f"Server information found in HTML comment: {comment.strip()}",
                "affected_resource": target_url
            })

    return findings


# def check_server_version(target_url):
#     response = requests.get(target_url)
#     findings = []
#
#     if "Server" in response.headers:
#         server_info = response.headers["Server"]
#         findings.append({
#             "vulnerability_name": "Outdated Software",
#             "severity": "HIGH",
#             "description": f"Server version {server_info} might be outdated.",
#             "affected_resource": target_url
#         })
#     return findings

def check_sensitive_info_in_html(target_url):
    findings = []

    try:
        response = requests.get(target_url, timeout=10)
        if response.status_code != 200:
            return [{"vulnerability_name": "Failed to Fetch Page",
                     "severity": "LOW",
                     "description": "Could not retrieve the page contents.",
                     "affected_resource": target_url}]

        soup = BeautifulSoup(response.text, 'html.parser')

        comments = soup.find_all(string=lambda text: isinstance(text, str) and any(
            keyword in text.lower() for keyword in ["server", "api_key", "password", "db"]))
        for comment in comments:
            findings.append({
                "vulnerability_name": "Sensitive Comment Found",
                "severity": "MEDIUM",
                "description": f"Suspicious comment in HTML: {comment.strip()}",
                "affected_resource": target_url
            })

        meta_tags = soup.find_all("meta", {"name": ["generator", "server"]})
        for meta in meta_tags:
            findings.append({
                "vulnerability_name": "Server Info Leaked in Meta Tag",
                "severity": "MEDIUM",
                "description": f"Meta tag found: {meta}",
                "affected_resource": target_url
            })

        scripts = soup.find_all("script")
        for script in scripts:
            if script.string and any(
                    keyword in script.string.lower() for keyword in ["key", "auth", "token", "secret"]):
                findings.append({
                    "vulnerability_name": "Sensitive Data in JavaScript",
                    "severity": "HIGH",
                    "description": f"Potentially sensitive JavaScript found: {script.string[:100]}...",
                    "affected_resource": target_url
                })

    except requests.RequestException as e:
        findings.append({
            "vulnerability_name": "Request Error",
            "severity": "LOW",
            "description": str(e),
            "affected_resource": target_url
        })

    return findings


def check_open_ports(target):
    """Scan for open ports on the target server."""
    ports = [21, 22, 23, 80, 443, 3306, 8080]
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return [{"vulnerability_name": "Open Port Detected",
             "severity": "MEDIUM",
             "description": f"Port {port} is open and may be vulnerable.",
             "affected_resource": f"{target}:{port}"}
            for port in open_ports]


def check_exposed_error_messages(url):
    """Check if error messages reveal sensitive data."""
    error_payloads = ["' OR 1=1 --", "<script>alert('XSS')</script>"]
    exposed_errors = []

    for payload in error_payloads:
        response = requests.get(f"{url}/?id={payload}")
        if "error" in response.text.lower() or "warning" in response.text.lower():
            exposed_errors.append(payload)

    return [{"vulnerability_name": "Exposed Error Message",
             "severity": "HIGH",
             "description": "Server responds with an error message that may reveal sensitive details.",
             "affected_resource": url}]


def check_security_misconfigurations(target_url):
    findings = []

    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    ip_address = socket.gethostbyname(domain)

    findings.extend(check_default_accounts(target_url))
    # findings.extend(run_scan(target_url))
    findings.extend(check_unpublished_urls_and_sensitive_files(target_url))
    findings.extend(check_security_headers(target_url))
    # findings.extend(check_sensitive_info_in_html(target_url))
    findings.extend(check_server_info_in_html(target_url))
    findings.extend(check_open_ports(ip_address))
    findings.extend(check_exposed_error_messages(target_url))

    return findings
