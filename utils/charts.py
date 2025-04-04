import json
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
from collections import Counter


# Sample JSON response
# data = {
#     "detail": "Scan completed successfully!",
#     "scan_id": 218,
#     "target_url": "https://badssl.com/",
#     "findings": [
#         {"vulnerability_name": "Unpublished URLs Are Not Blocked", "severity": "MEDIUM", "cvss_score": 4.3},
#         {"vulnerability_name": "Missing Security Headers", "severity": "INFO", "cvss_score": 5.3},
#         {"vulnerability_name": "Server Info Leaked in HTML", "severity": "MEDIUM", "cvss_score": 5.1},
#         {"vulnerability_name": "Open Port Detected", "severity": "MEDIUM", "cvss_score": 5.0},
#         {"vulnerability_name": "Request Failure", "severity": "INFO", "cvss_score": 7.8},
#         {"vulnerability_name": "Outdated Software", "severity": "HIGH", "cvss_score": 7.5},
#         {"vulnerability_name": "Outbound Connections to Internet Allowed", "severity": "MEDIUM", "cvss_score": 5.3}
#     ]
# }

# vulnerabilities = Vulnerability.objects.all()
#
# # Extract relevant data
# vulnerability_names = [v.vulnerability_name for v in vulnerabilities]
# severities = [v.severity for v in vulnerabilities]
# cvss_scores = [v.cvss_score for v in vulnerabilities]
#
# # Count occurrences of each severity level
# severity_counts = Counter(severities)
#
#
#
# # Bar Chart - Severity Distribution
# plt.figure(figsize=(8, 5))
# sns.barplot(x=list(severity_counts.keys()), y=list(severity_counts.values()), hue=list(severity_counts.keys()), legend=False)
# plt.title("Vulnerability Severity Distribution")
# plt.xlabel("Severity Level")
# plt.ylabel("Count")
# plt.show()
#
# # Pie Chart - Severity Proportion
# plt.figure(figsize=(6, 6))
# plt.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%', colors=["red", "orange", "blue"])
# plt.title("Severity Proportion")
# plt.show()
#
#
# # Scatter Plot - CVSS Score vs. Findings
# fig = px.scatter(
#     x=cvss_scores,
#     y=vulnerability_names,
#     color=severities,
#     size=cvss_scores,
#     title="CVSS Score vs. Vulnerabilities",
#     labels={"x": "CVSS Score", "y": "Vulnerability Name"}
# )
# fig.show()
#
#
# # Bar Chart - CVSS Score per Vulnerability
# plt.figure(figsize=(10, 5))
# sns.barplot(y=vulnerability_names, x=cvss_scores, hue=cvss_scores, legend=False)
# plt.xlabel("CVSS Score")
# plt.ylabel("Vulnerability")
# plt.title("CVSS Scores of Detected Vulnerabilities")
# plt.show()

import requests

# Fetch API Data
url = "http://127.0.0.1:8000/api/app/vulnerabilities/statistics/"

try:
    response = requests.get(url)

    print("Status Code:", response.status_code)
    print("Raw Response:", response.text)

    # Check if response is valid JSON
    if response.status_code == 200:
        data = response.json()
        print("Parsed JSON:", data)
        severity_counts = data["severity_distribution"]
        findings = data.get("findings", [])

        cvss_scores = [f["cvss_score"] if f["cvss_score"] is not None else 0 for f in findings]
        vulnerability_names = [f["vulnerability_name"] for f in findings]
        # line Chart - Severity Distribution
        plt.figure(figsize=(12, 6))
        sns.lineplot(x=cvss_scores, y=vulnerability_names,marker="o", linestyle="-", color="b")
        plt.title("Vulnerability Severity Distribution")
        plt.xlabel("Severity Level")
        plt.ylabel("Count")
        plt.grid(True)
        plt.show()

    else:
        print("Error: Received status code", response.status_code)

except requests.exceptions.RequestException as e:
    print("Request failed:", e)