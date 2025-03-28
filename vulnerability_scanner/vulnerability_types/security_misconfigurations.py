import requests, json, re, time
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import subprocess
import logging
from celery import shared_task
from collections import defaultdict
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options


nikto_path = "/usr/local/bin/nikto"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# def run_scan(target_url):
#     """Runs a scan and returns structured findings."""
#     findings = []
#
#     try:
#         command = ["nikto", "-h", target_url]
#         # command = ['wapiti', '-u', target_url, '-f', 'json', '-o', 'wapiti_results.json'] #wapiti3
#         result = subprocess.run(command, capture_output=True, text=True)
#
#         output = result.stdout
#         # output = result.communicate() #wapiti3
#
#         try:
#             with open('wapiti_results.json', 'r') as file:
#                 wapiti_data = json.load(file)
#
#             for vuln in wapiti_data.get("vulnerabilities", []):
#                 findings.append({
#                     "vulnerability_name": vuln.get("name", "Unknown Vulnerability"),
#                     "severity": vuln.get("severity", "UNKNOWN"),
#                     "description": vuln.get("description", "No description available"),
#                     "affected_resource": vuln.get("url", target_url)
#                 })
#
#         except FileNotFoundError:
#             findings.append({
#                 "vulnerability_name": "Wapiti Scan Error",
#                 "severity": "LOW",
#                 "description": "Wapiti results file not found.",
#                 "affected_resource": target_url
#             })
#
#         return findings
#
#     except Exception as e:
#         findings.append({
#             "vulnerability_name": "Wapiti Scan Error",
#             "severity": "LOW",
#             "description": str(e),
#             "affected_resource": target_url
#         })
#

def run_nmap_scan(target_url):
    findings = []

    try:
        domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        ip_address = socket.gethostbyname(domain)
    except Exception as e:
        return [{
            "vulnerability_name": "DNS Resolution Failed",
            "severity": "HIGH",
            "description": str(e),
            "affected_resource": target_url
        }]

    commands = {
        "default_accounts": f"nmap -p 80,443 --script=http-default-accounts {ip_address}",
        "outdated_software": f"nmap --script=http-server-header,ssl-cert,vulners {ip_address}",
        "unprotected_files": f"nmap --script=http-enum,http-robots.txt {ip_address}",
        "unused_features": f"nmap --script=http-methods {ip_address}",
        "weak_ssl": f"nmap --script=ssl-enum-ciphers {ip_address}",
    }

    for check, cmd in commands.items():
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stderr)
            print(result.stdout)
            if result.stderr:
                findings.append({
                    "vulnerability_name": f"{check.replace('_', ' ').title()} Scan Error",
                    "severity": "LOW",
                    "description": result.stderr,
                    "affected_resource": target_url
                })
            else:
                findings.append({
                    "vulnerability_name": check.replace("_", " ").title(),
                    "severity": "MEDIUM",
                    "description": result.stdout,
                    "affected_resource": target_url
                })

        except Exception as e:
            findings.append({
                "vulnerability_name": f"{check.replace('_', ' ').title()} Scan Error",
                "severity": "LOW",
                "description": str(e),
                "affected_resource": target_url
            })

    return findings


# def attempt_login_with_all_combinations(target_url):
#     """Attempts to login with all combinations of usernames/emails and passwords."""
#     default_paths = ["/admin", "/login", "/user", "/wp-login.php", "/practice-test-login"]
#     findings = []
#
#     username_email_list = ["admin", "admin@example.com", "root", "root@example.com", "student"]
#     password_list = ["admin", "password", "123456", "qwerty", "letmein", "Password123"]
#
#     for path in default_paths:
#         web_url = target_url.rstrip("/") + path
#         print(web_url)
#         try:
#             response = requests.get(web_url)
#             if response.status_code != 200:
#                 continue
#
#             soup = BeautifulSoup(response.content, 'html.parser')
#             form = soup.find('form')
#             action = form.get('action') if form else target_url
#
#             login_url = target_url.rstrip("/") + action
#             print(f"Attempting login at: {login_url}")
#             username_field = soup.find('input', {'name': 'username'})
#             email_field = soup.find('input', {'name': 'email'})
#
#             field_name = 'username' if username_field else 'email' if email_field else None
#             print(field_name)
#             for username_email in username_email_list:
#                 print(username_field)
#                 for password in password_list:
#                     login_data = {field_name: username_email, "password": password} if field_name else None
#                     print(login_data)
#                     login_data_username = {"username": username_email, "password": password}
#                     login_data_email = {"email": username_email, "password": password}
#                     print(login_data_email)
#                     try:
#                         if login_data:
#                             print(login_data)
#                             response = requests.post(login_url, data=login_data, )
#                         else:
#                             response_username = requests.post(login_url, data=login_data_username, )
#                             response_email = requests.post(login_url, data=login_data_email, )
#
#                         # Check response text for successful login
#                         success_messages = ["Welcome", "Login successful", "Dashboard"]
#                         if login_data and any(msg in response.text for msg in success_messages):
#                             findings.append({
#                                 "vulnerability_name": "Weak Password Detected",
#                                 "severity": "HIGH",
#                                 "description": f"Login page {path} accepts weak password '{password}' for {username_email}",
#                                 "affected_resource": path
#                             })
#                         elif not login_data:
#                             if any(msg in response_username.text for msg in success_messages):
#                                 findings.append({
#                                     "vulnerability_name": "Weak Password Detected",
#                                     "severity": "HIGH",
#                                     "description": f"Login page {path} accepts weak password '{password}' for {username_email} using 'username'",
#                                     "affected_resource": path
#                                 })
#                             if any(msg in response_email.text for msg in success_messages):
#                                 findings.append({
#                                     "vulnerability_name": "Weak Password Detected",
#                                     "severity": "HIGH",
#                                     "description": f"Login page {path} accepts weak password '{password}' for {username_email} using 'email'",
#                                     "affected_resource": path
#                                 })
#                     except requests.RequestException as e:
#                         print(f"Error attempting login at {web_url} with {username_email}:{password} -> {e}")
#         except requests.RequestException as e:
#             print(f"Error accessing {web_url}: {e}")
#
#     return findings


# def check_default_accounts(target_url):
#     DEFAULT_CREDENTIALS = [("admin", "admin"), ("root", "root"), ("user", "password")]
#
#     login_paths = ["/admin", "/login", "/user", "/wp-login.php"]
#     findings = []
#
#     for path in login_paths:
#         url = target_url.rstrip("/") + path
#         response = requests.get(url)
#         if response.status_code == 200:
#             soup = BeautifulSoup(response.content, 'html.parser')
#             email_field = soup.find('input', {'name': 'email'})
#             username_field_name = 'email' if email_field else 'username'
#
#             for username, password in DEFAULT_CREDENTIALS:
#                 login_data = {username_field_name: username, "password": password}
#
#                 csrf_token_field = soup.find('input', {'name': '_csrf_token'})
#                 if csrf_token_field:
#                     login_data['_csrf_token'] = csrf_token_field['value']
#
#                 login_response = requests.post(url, data=login_data)
#                 login_soup = BeautifulSoup(login_response.content, 'html.parser')
#
#                 if "Welcome" in login_response.text or "Login successful" in login_response.text:
#                     findings.append({
#                         "vulnerability_name": "Default Account Detected",
#                         "severity": "HIGH",
#                         "description": f"Login page {url} accepts default credentials {username}:{password}",
#                         "affected_resource": url
#                     })
#                 elif "Invalid username or password" not in login_response.text:
#                     # If no clear success or failure message, consider it potentially vulnerable
#                     findings.append({
#                         "vulnerability_name": "Potential Default Account Detected",
#                         "severity": "MEDIUM",
#                         "description": f"Login page {url} may accept default credentials {username}:{password}",
#                         "affected_resource": url
#                     })
#
#                 # if login_response.status_code == 200:
#                 #     findings.append({
#                 #         "vulnerability_name": "Default Account Detected",
#                 #         "severity": "HIGH",
#                 #         "description": f"Login page {url} accepts default credentials {username}:{password}",
#                 #         "affected_resource": url
#                 #     })
#     return findings


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


# def check_password_policy(target_url):
#     policy_url = target_url.rstrip("/") + "/password-policy"
#     response = requests.get(policy_url)
#     findings = []
#
#     if response.status_code == 200 and "min_length" in response.json():
#         if response.json()["min_length"] < 8:
#             findings.append({
#                 "vulnerability_name": "Weak Password Policy",
#                 "severity": "MEDIUM",
#                 "description": "Password policy allows weak passwords.",
#                 "affected_resource": policy_url
#             })
#     return findings

LOGIN_ENDPOINTS = ["/login", "/signin", "/enter", "/auth", "/account/login", "/practice-test-login"]
POSSIBLE_USERNAMES = ["user", "admin", "root", "student"]
POSSIBLE_PASSWORDS = ["password", "pass", "pwd", "admin", "root", "12345678", "Password123"]
# POSSIBLE_USERNAMES = ["email", "username", "user", "login", "admin", "root", "student"]
# POSSIBLE_PASSWORDS = ["password", "pass", "pwd", "admin", "root", "12345678", "Password123"]

def detect_login_page(driver, base_url):
    """Detects if a login form is present on the homepage or after clicking a button."""

    # Check if there is a 'Sign in' or 'Login' button
    login_buttons = driver.find_elements(By.XPATH, "//button[contains(text(), 'Sign in') or contains(text(), 'Login')]")

    if login_buttons:
        print("Login button found on homepage, clicking...")
        login_buttons[0].click()
        time.sleep(3)  # Wait for the modal or redirection

        return driver.current_url  # Return the new URL after clicking

    # If no button, try predefined login URLs
    for endpoint in LOGIN_ENDPOINTS:
        login_url = f"{base_url.rstrip('/')}{endpoint}"
        driver.get(login_url)
        time.sleep(2)

        if "login" in driver.current_url or "signin" in driver.current_url:
            print(f"Login page detected: {login_url}")
            return login_url

    print("No login form found.")
    return None

def find_login_form(driver):
    """Attempts to find login input fields on the page."""

    possible_usernames = ["email", "username", "user", "login", "admin", "root", "student"]
    possible_passwords = ["password", "pass", "pwd", "admin", "root", "12345678", "Password123"]

    username_input = None
    password_input = None
    login_button = None

    # Find input fields
    inputs = driver.find_elements(By.TAG_NAME, "input")
    for input_field in inputs:
        name_attr = input_field.get_attribute("name") or ""
        type_attr = input_field.get_attribute("type") or ""

        if any(key in name_attr.lower() for key in POSSIBLE_USERNAMES) and type_attr == "text":
            username_input = input_field
        if any(key in name_attr.lower() for key in POSSIBLE_PASSWORDS) and type_attr == "password":
            password_input = input_field

    # Find submit button
    buttons = driver.find_elements(By.TAG_NAME, "button")
    for button in buttons:
        button_text = button.text.lower()
        if "sign in" in button_text or "log in" in button_text or "submit" in button_text:
            login_button = button
            break

    return username_input, password_input, login_button

def check_default_web_credentials(target_url):
    """Detects login page, finds login form, and tests default credentials."""

    findings = []

    options = Options()
    options.add_argument("--headless")  # Run in headless mode
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)

    try:
        for endpoint in LOGIN_ENDPOINTS:
            login_url = f"{target_url.rstrip('/')}{endpoint}"
            print(f"Trying: {login_url}")
            driver.get(login_url)
            time.sleep(3)

            # Find login form dynamically
            username_input = None
            password_input = None
            login_button = None

            inputs = driver.find_elements(By.TAG_NAME, "input")
            for input_field in inputs:
                name_attr = input_field.get_attribute("name") or ""
                type_attr = input_field.get_attribute("type") or ""

                if any(key in name_attr.lower() for key in POSSIBLE_USERNAMES) and type_attr in ["text", "email"]:
                    username_input = input_field
                if any(key in name_attr.lower() for key in POSSIBLE_PASSWORDS) and type_attr == "password":
                    password_input = input_field

            buttons = driver.find_elements(By.TAG_NAME, "button") + driver.find_elements(By.TAG_NAME, "input")
            for button in buttons:
                button_text = button.get_attribute("value") or button.text
                if any(keyword in button_text.lower() for keyword in ["login", "sign in", "submit"]):
                    login_button = button
                    break

            if username_input and password_input and login_button:
                print(f"Login form detected at {login_url}")

                for username in POSSIBLE_USERNAMES:
                    print(username)

                    for password in POSSIBLE_PASSWORDS:
                        print(password)
                        username_input.clear()
                        password_input.clear()

                        username_input.send_keys(username)
                        password_input.send_keys(password)
                        login_button.click()
                        time.sleep(3)  # Wait for response

                        # Detect successful login
                        if "incorrect" in driver.page_source.lower() or "invalid" in driver.page_source.lower():
                            print(f"Failed login attempt: {username} / {password}")
                        elif driver.current_url != login_url:  # URL changed -> likely logged in
                            print(f"Possible default credentials working: {username} / {password}")
                            findings.append({
                                "vulnerability_name": "Default Credentials Found",
                                "severity": "HIGH",
                                "description": f"Possible default credentials: {username} / {password}",
                                "affected_resource": login_url
                            })
                            return findings  # Stop testing after finding a valid login

    except Exception as e:
        print(f"Error: {e}")

    finally:
        driver.quit()

    return findings

# def check_default_web_credentials(target_url):
#     """Automatically detects login page and checks for default credentials."""
#
#     findings = []
#
#     options = Options()
#     options.add_argument("--headless")
#     options.add_argument("--disable-gpu")
#     options.add_argument("--no-sandbox")
#
#     service = Service(ChromeDriverManager().install())
#     driver = webdriver.Chrome(service=service, options=options)
#
#     try:
#         for endpoint in LOGIN_ENDPOINTS:
#             login_url = f"{target_url.rstrip('/')}{endpoint}"
#             print(f"Trying: {login_url}")
#             driver.get(login_url)
#             time.sleep(2)
#
#             # username_input, password_input, login_button = find_login_form(driver)
#             username_input = driver.find_element(By.XPATH,"//input[contains(@name, 'user') or contains(@name, 'email')]")
#             password_input = driver.find_element(By.XPATH, "//input[contains(@name, 'pass')]")
#             login_button = driver.find_element(By.XPATH,"//button[contains(text(), 'Login') or contains(text(), 'Sign in')]")
#
#             if username_input and password_input and login_button:
#                 print(f"Login form detected at {login_url}")
#
#                 for username in POSSIBLE_USERNAMES:
#                     for password in POSSIBLE_PASSWORDS:
#                         username_input.clear()
#                         password_input.clear()
#
#                         username_input.send_keys(username)
#                         print(username_input)
#
#                         password_input.send_keys(password)
#                         print(password_input)
#                         login_button.click()
#                         time.sleep(2)
#
#                         if "incorrect" in driver.page_source.lower() or "invalid" in driver.page_source.lower():
#                             print(f"Failed login attempt: {username} / {password}")
#                             print("Default credentials failed (good security).")
#                         else:
#                             print("Possible default credentials working!")
#                         break
#             else:
#                 print("No login form found.")
#
#     except Exception as e:
#         print(f"Error: {e}")
#
#     finally:
#         driver.quit()
#
#     return findings

# def check_default_web_credentials(target_url, login_endpoints=None):
#     """Checks if the web application allows default credentials."""
#
#     # Common login endpoints to check
#     if login_endpoints is None:
#         login_endpoints = [
#             "/login", "/admin", "/signin", "/user/login",
#             "/account/login", "/auth", "/dashboard/login"
#         ]
#
#     default_credentials = [
#         ("admin", "admin"),
#         ("admin", "password"),
#         ("root", "toor"),
#         ("user", "1234"),
#     ]
#
#     headers = {"User-Agent": "Mozilla/5.0"}
#
#     valid_login_pages = []
#
#     for endpoint in login_endpoints:
#         login_url = target_url.rstrip("/") + endpoint
#         response = requests.get(login_url, headers=headers, allow_redirects=True, timeout=5)
#
#         if response.status_code in [200, 403]:
#             valid_login_pages.append(login_url)
#
#     if not valid_login_pages:
#         return {"vulnerability_name": "No Valid Login Page Found", "severity": "LOW", "affected_resource": target_url}
#
#     findings = []
#
#     for login_url in valid_login_pages:
#         for username, password in default_credentials:
#             data = {"username": username, "password": password}  # Modify keys as needed
#             response = requests.post(login_url, data=data, headers=headers, allow_redirects=False)
#
#             # If login is successful (200 OK or redirects to dashboard)
#             if response.status_code in [200, 302, 301]:
#                 findings.append({
#                     "vulnerability_name": "Default Credentials Allowed",
#                     "severity": "HIGH",
#                     "description": f"Login successful with default credentials ({username}:{password})",
#                     "affected_resource": login_url
#                 })
#
#     if not findings:
#         findings.append({
#             "vulnerability_name": "No Default Credentials Found",
#             "severity": "LOW",
#             "affected_resource": target_url
#         })
#
#     return findings

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

    # required_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
    required_headers = {
        "Strict-Transport-Security": "Enforces HTTPS connections.",
        "Content-Security-Policy": "Defines allowed sources of content.",
        "X-Frame-Options": "Prevents clickjacking attacks.",
        "X-Content-Type-Options": "Prevents MIME-sniffing attacks.",
        "X-XSS-Protection": "Enables cross-site scripting protection.",
        "Referrer-Policy": "Controls referrer information sent with requests.",
        "Feature-Policy": "Defines allowed browser features.",
        "Public-Key-Pins": "Associates a specific public key with a web server (obsolete).",
        "Expect-CT": "Enforces Certificate Transparency for certificate validation."
    }

    for header, description in required_headers.items():
        if header not in headers:
            missing_headers.append((header, description))

    return [{"vulnerability_name": "Missing Security Headers",
             "severity": "LOW",
             "description": f"{header} header is missing.{description}",
             "affected_resource": url}
            for header, description in missing_headers]


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


# check-server-version
KNOWN_LATEST_VERSIONS = {
    "Apache": "2.4.58",
    "nginx": "1.25.3",
    "Microsoft-IIS": "10.0",
    "LiteSpeed": "6.1",
    "Caddy": "2.7.6",
    "Tomcat": "10.1.16",
    "OpenLiteSpeed": "1.7.20",
    "Cloudflare": "2.11.0",
    "Google Web Server": "2.4",
    "Amazon Elastic Load Balancer": "2",
    "Node.js": "21.7.3",
    "Gunicorn": "21.2.0",
    "uWSGI": "2.0.24",
    "Tengine": "2.3.3",
    "H2O": "2.3.0-beta2",
    "Cherokee": "1.2.104",
    "Cowboy": "2.10.0"
}


def extract_server_info(server_header):
    """Extracts server name and version from the Server header."""
    match = re.match(r"([\w\-]+)[/ ]([\d\.]+)", server_header)
    if match:
        return match.group(1), match.group(2)  # (Server Name, Version)
    return server_header, None


def check_server_version(target_url):
    try:
        response = requests.get(target_url)
        findings = []

        if "Server" in response.headers:
            server_info = response.headers["Server"]
            server_name, server_version = extract_server_info(server_info)

            if server_name in KNOWN_LATEST_VERSIONS and server_version:
                latest_version = KNOWN_LATEST_VERSIONS[server_name]

                if server_version < latest_version:
                    findings.append({
                        "vulnerability_name": "Outdated Software",
                        "severity": "HIGH",
                        "description": f"{server_name} version {server_version} is outdated. Latest version is {latest_version}.",
                        "affected_resource": target_url
                    })
            else:
                findings.append({
                    "vulnerability_name": "Server Information Disclosure",
                    "severity": "MEDIUM",
                    "description": f"Server is exposing its version: {server_info}. Consider hiding this information.",
                    "affected_resource": target_url
                })
        return findings

    except requests.RequestException as e:
        return [{"error": f"Failed to connect to {target_url}: {str(e)}"}]


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
        try:
            response = requests.get(f"{url}/?id={payload}")
            if "error" in response.text.lower() or "warning" in response.text.lower():
                exposed_errors.append({
                    "payload": payload,
                    "response_text": response.text[:100]  # Show a snippet of the response
                })
        except Exception as e:
            print(f"Error checking {url} with payload {payload}: {e}")

    if exposed_errors:
        return [{"vulnerability_name": "Exposed Error Message",
                 "severity": "HIGH",
                 "description": f"Server responds with an error message that may reveal sensitive details. Payloads used: {', '.join([err['payload'] for err in exposed_errors])}.",
                 "affected_resource": url,
                 # "evidence": "\n".join([f"Payload: {err['payload']}\nResponse Snippet: {err['response_text']}" for err in exposed_errors])
                 }]
    else:
        return [{"vulnerability_name": "No Exposed Error Messages Found",
                 "severity": "INFO",
                 "description": f"No error messages revealing sensitive details were found for {url}.",
                 "affected_resource": url}]


# check-directory-traversal
LINUX_PATHS = [
    "../../../../etc/passwd",  # User accounts
    "../../../../etc/shadow",  # Encrypted passwords
    "../../../../etc/group",  # User groups
    "../../../../etc/hosts",  # Hostname/IP mapping
    "../../../../etc/hostname",  # Server hostname
    "../../../../etc/network/interfaces",  # Network settings
    "../../../../root/.bash_history",  # Command history
    "../../../../home/user/.ssh/id_rsa",  # SSH private key
    "../../../../var/log/auth.log",  # Authentication logs
    "../../../../var/log/syslog",  # System logs
    "../../../../var/log/apache2/access.log",  # Apache access logs
    "../../../../var/log/apache2/error.log",  # Apache error logs
    "../../../../var/log/nginx/access.log",  # Nginx access logs
    "../../../../var/log/nginx/error.log",  # Nginx error logs
    "../../../../usr/local/apache2/conf/httpd.conf",  # Apache config
    "../../../../etc/nginx/nginx.conf",  # Nginx config
    "../../../../etc/my.cnf",  # MySQL configuration
    "../../../../var/lib/mysql/mysql.sock",  # MySQL socket file
    "../../../../var/lib/mysql/mysql-bin.index",  # MySQL binlog index
]

WINDOWS_PATHS = [
    "../../../../windows/win.ini",  # Windows system config
    "../../../../windows/system32/drivers/etc/hosts",  # Hosts file
    "../../../../windows/system32/config/sam",  # Windows user database
    "../../../../windows/system32/config/system",  # System configuration
    "../../../../windows/system32/config/security",  # Security policy
    "../../../../windows/system32/config/software",  # Installed software info
    "../../../../windows/system32/config/regback/system",  # Registry backup
    "../../../../windows/system32/logfiles/srt/srttrail.txt",  # System logs
    "../../../../windows/debug/NetSetup.log",  # Network setup log
    "../../../../Users/Public/Desktop",  # Public desktop files
    "../../../../Users/<USERNAME>/Desktop",  # User desktop files
    "../../../../Users/<USERNAME>/Documents",  # User documents
    "../../../../Users/<USERNAME>/Downloads",  # User downloads
    "../../../../Users/<USERNAME>/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",  # Startup programs
]

WEB_APP_PATHS = [
    "../../../../var/www/html/config.php",  # PHP config file
    "../../../../var/www/html/wp-config.php",  # WordPress config
    "../../../../var/www/html/.env",  # Laravel or Node.js environment file
    "../../../../var/www/html/.htaccess",  # Apache access rules
    "../../../../var/www/html/.htpasswd",  # Apache password protection file
    "../../../../var/www/html/admin/config.php",  # Admin panel config
    "../../../../var/www/html/db.php",  # Database connection file
    "../../../../var/www/html/includes/config.php",  # Include config file
    "../../../../var/www/html/application/config/config.php",  # CodeIgniter config
    "../../../../var/www/html/protected/config/main.php",  # Yii framework config
    "../../../../var/www/html/storage/logs/laravel.log",  # Laravel logs
]

CLOUD_CONTAINER_PATHS = [
    "../../../../.docker/config.json",  # Docker config
    "../../../../.kube/config",  # Kubernetes config
    "../../../../etc/kubernetes/admin.conf",  # Kubernetes admin config
    "../../../../etc/kubernetes/kubelet.conf",  # Kubernetes kubelet config
    "../../../../root/.aws/credentials",  # AWS credentials file
    "../../../../root/.aws/config",  # AWS config file
    "../../../../root/.gcp/credentials.json",  # Google Cloud credentials
    "../../../../etc/passwd",  # Containerized system user info
]

PAYLOADS = LINUX_PATHS + WINDOWS_PATHS + WEB_APP_PATHS + CLOUD_CONTAINER_PATHS


def check_directory_traversal(target_url, param="file"):

    findings = defaultdict(lambda: {
        "vulnerability_name": "",
        "severity": "",
        "description": "",
        "affected_resource": target_url,
        # "details": []
    })

    for payload in PAYLOADS:
        test_url = f"{target_url}?{param}={payload}"

        try:
            response = requests.get(test_url, timeout=5)

            if response.status_code == 200:
                if any(keyword in response.text for keyword in ["root:x:", "Windows Registry Editor", "[fonts]"]):
                    key = "HIGH_200"
                    findings[key]["vulnerability_name"] = "Directory Traversal"
                    findings[key]["severity"] = "HIGH"
                    findings[key]["description"] = f"Potential directory traversal detected at {test_url}."
                    # findings[key]["details"].append(test_url)

            elif response.status_code in [403, 400]:
                key = "LOW_403"
                findings[key]["vulnerability_name"] = "Directory Traversal Prevention"
                findings[key]["severity"] = "LOW"
                findings[key][
                    "description"] = f"Possible protection against directory traversal (returned {response.status_code})."
                # findings[key]["details"].append(test_url)

        except requests.RequestException as e:
            findings["ERROR"]["vulnerability_name"] = "Request Failure"
            findings["ERROR"]["severity"] = "INFO"
            findings["ERROR"]["description"] = f"Failed to connect to {target_url}: {str(e)}"

    results = list(findings.values())

    if not results:
        print("[!] No findings detected.")

    return results


def check_security_misconfigurations(target_url):
    findings = []

    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    ip_address = socket.gethostbyname(domain)

    findings.extend(check_default_web_credentials(target_url))
    # findings.extend(run_nmap_scan(target_url))
    # findings.extend(async_to_sync(run_scan)(target_url))
    findings.extend(check_unpublished_urls_and_sensitive_files(target_url))
    # findings.extend(check_default_web_credentials(target_url))
    findings.extend(check_security_headers(target_url))
    # findings.extend(check_sensitive_info_in_html(target_url))
    findings.extend(check_server_info_in_html(target_url))
    findings.extend(check_server_version(target_url))
    findings.extend(check_open_ports(ip_address))
    findings.extend(check_exposed_error_messages(target_url))
    findings.extend(check_directory_traversal(target_url))

    return findings
