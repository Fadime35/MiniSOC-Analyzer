# analyzer.py

from collections import defaultdict
from colorama import Fore, Style, init
import pandas as pd

init(autoreset=True)  # Colorama için

# ----------------------------
# MITRE ATT&CK mapping
# ----------------------------
mitre_mapping = {
    "Brute Force": {"Tactic": "Credential Access", "Technique": "Brute Force", "ID": "T1110"},
    "SQL Injection": {"Tactic": "Initial Access", "Technique": "SQL Injection", "ID": "T1190"},
    "XSS Attack": {"Tactic": "Initial Access / Execution", "Technique": "Cross-Site Scripting", "ID": "T1059.007"},
    "Port Scan": {"Tactic": "Reconnaissance", "Technique": "Port Scanning", "ID": "T1046"},
}

# ----------------------------
# Log okuma fonksiyonu
# ----------------------------
def read_log(file):
    with open(file, "r") as f:
        return f.readlines()

# ----------------------------
# Logları oku
# ----------------------------
auth_logs = read_log("logs/auth.log")
web_logs = read_log("logs/web.log")
network_logs = read_log("logs/network.log")

alerts = []

# ----------------------------
# Brute Force Detection
# ----------------------------
failed_attempts = defaultdict(int)
for line in auth_logs:
    if "FAILED" in line:
        ip = line.split("ip:")[1].strip()
        failed_attempts[ip] += 1
        if failed_attempts[ip] == 3:
            alerts.append({
                "type": "Brute Force",
                "ip": ip,
                "risk": "HIGH",
                "description": "Multiple failed login attempts detected"
            })

# ----------------------------
# SQL Injection Detection
# ----------------------------
for line in web_logs:
    if "' OR '1'='1" in line:
        ip = line.split("ip:")[1].strip()
        alerts.append({
            "type": "SQL Injection",
            "ip": ip,
            "risk": "HIGH",
            "description": "Possible SQL injection attempt"
        })

# ----------------------------
# XSS Detection
# ----------------------------
for line in web_logs:
    if "<script>" in line:
        ip = line.split("ip:")[1].strip()
        alerts.append({
            "type": "XSS Attack",
            "ip": ip,
            "risk": "MEDIUM",
            "description": "Cross-site scripting attempt detected"
        })

# ----------------------------
# Port Scan Detection
# ----------------------------
connections = defaultdict(set)
for line in network_logs:
    if "CONNECTION" in line:
        ip = line.split("ip:")[1].split()[0]
        port = line.split("port:")[1].strip()
        connections[ip].add(port)
        if len(connections[ip]) == 3:
            alerts.append({
                "type": "Port Scan",
                "ip": ip,
                "risk": "MEDIUM",
                "description": "Multiple ports accessed in short time"
            })

# ----------------------------
# Terminalde alertleri renkli yazdır
# ----------------------------
print("\n=== SECURITY ALERT REPORT ===\n")
for alert in alerts:
    if alert['risk'] == "HIGH":
        color = Fore.RED
    elif alert['risk'] == "MEDIUM":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    print(f"{color}[{alert['risk']}] {alert['type']}")
    print(f"{color}IP: {alert['ip']}")
    print(f"{color}Description: {alert['description']}")
    
    mitre = mitre_mapping.get(alert['type'], {})
    if mitre:
        print(f"{color}MITRE Tactic: {mitre['Tactic']}")
        print(f"{color}MITRE Technique: {mitre['Technique']} ({mitre['ID']})")
    print("-" * 40)

# ----------------------------
# report.txt dosyasına yaz
# ----------------------------
with open("report.txt", "w") as f:
    for alert in alerts:
        f.write(f"[{alert['risk']}] {alert['type']}\n")
        f.write(f"IP: {alert['ip']}\n")
        f.write(f"Description: {alert['description']}\n")
        if mitre_mapping.get(alert['type']):
            f.write(f"MITRE Tactic: {mitre_mapping[alert['type']]['Tactic']}\n")
            f.write(f"MITRE Technique: {mitre_mapping[alert['type']]['Technique']} ({mitre_mapping[alert['type']]['ID']})\n")
        f.write("-" * 40 + "\n")

# ----------------------------
# CSV / Excel export
# ----------------------------
df = pd.DataFrame(alerts)
df['MITRE Tactic'] = df['type'].apply(lambda x: mitre_mapping.get(x, {}).get('Tactic', ''))
df['MITRE Technique'] = df['type'].apply(lambda x: mitre_mapping.get(x, {}).get('Technique', ''))
df['MITRE ID'] = df['type'].apply(lambda x: mitre_mapping.get(x, {}).get('ID', ''))

df.to_csv("report.csv", index=False)
df.to_excel("report.xlsx", index=False)

print("\n Reports generated: report.txt, report.csv, report.xlsx")