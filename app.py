from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import socket
import threading
import time
import math
import re
import os
import ssl
import hashlib
import datetime
import requests

app = Flask(__name__, static_folder='static')
CORS(app)

# ─── Port Database ────────────────────────────────────────────────────────────
PORT_INFO = {
    21:    {"service": "FTP",        "risk": "high",   "cve": "CVE-2011-2523",  "desc": "Unencrypted file transfer. Credentials sent in plaintext."},
    22:    {"service": "SSH",        "risk": "medium", "cve": "CVE-2023-38408", "desc": "Secure Shell. Risk of brute-force if weak passwords used."},
    23:    {"service": "Telnet",     "risk": "high",   "cve": "CVE-2020-10188", "desc": "Completely unencrypted remote access. Deprecate immediately."},
    25:    {"service": "SMTP",       "risk": "medium", "cve": "CVE-2020-7247",  "desc": "Mail relay. Open relay can be abused for spam campaigns."},
    53:    {"service": "DNS",        "risk": "low",    "cve": "CVE-2020-1350",  "desc": "Domain Name System. Watch for DNS amplification attacks."},
    80:    {"service": "HTTP",       "risk": "low",    "cve": "CVE-2021-41773", "desc": "Unencrypted web traffic. Upgrade to HTTPS immediately."},
    110:   {"service": "POP3",       "risk": "medium", "cve": "CVE-2003-0143",  "desc": "Email retrieval. Unencrypted variant leaks credentials."},
    135:   {"service": "MSRPC",      "risk": "high",   "cve": "CVE-2003-0352",  "desc": "Windows RPC endpoint. Historic Blaster worm vector."},
    139:   {"service": "NetBIOS",    "risk": "high",   "cve": "CVE-2017-0143",  "desc": "Legacy Windows file sharing. EternalBlue exploit target."},
    143:   {"service": "IMAP",       "risk": "low",    "cve": "CVE-2021-38647", "desc": "Email protocol. Use TLS variant (993) instead."},
    443:   {"service": "HTTPS",      "risk": "low",    "cve": "N/A",            "desc": "Encrypted web traffic. Verify TLS version and certificate."},
    445:   {"service": "SMB",        "risk": "high",   "cve": "CVE-2017-0144",  "desc": "EternalBlue / WannaCry ransomware vector. Patch immediately."},
    1433:  {"service": "MSSQL",      "risk": "high",   "cve": "CVE-2020-0618",  "desc": "SQL Server exposed to network. Never expose DB to internet."},
    3306:  {"service": "MySQL",      "risk": "high",   "cve": "CVE-2016-6662",  "desc": "MySQL database exposed. Restrict access to localhost only."},
    3389:  {"service": "RDP",        "risk": "high",   "cve": "CVE-2019-0708",  "desc": "BlueKeep vulnerability. Gate behind VPN immediately."},
    5432:  {"service": "PostgreSQL", "risk": "medium", "cve": "CVE-2019-10164", "desc": "Postgres exposed. Restrict with pg_hba.conf rules."},
    5900:  {"service": "VNC",        "risk": "high",   "cve": "CVE-2019-15681", "desc": "Remote desktop unencrypted. Extremely dangerous if exposed."},
    6379:  {"service": "Redis",      "risk": "high",   "cve": "CVE-2022-0543",  "desc": "Redis with no-auth default. Full remote code execution possible."},
    8080:  {"service": "HTTP-Alt",   "risk": "medium", "cve": "CVE-2021-42013", "desc": "Alternate HTTP / dev server. Often misconfigured in production."},
    8443:  {"service": "HTTPS-Alt",  "risk": "low",    "cve": "N/A",            "desc": "Alternate HTTPS port. Verify certificate validity."},
    27017: {"service": "MongoDB",    "risk": "high",   "cve": "CVE-2017-14227", "desc": "MongoDB no-auth default. Millions of DBs were exposed historically."},
    9200:  {"service": "Elasticsearch","risk":"high",  "cve": "CVE-2021-22145", "desc": "Elasticsearch exposed. Data leak risk without authentication."},
    2181:  {"service": "ZooKeeper",  "risk": "high",   "cve": "CVE-2019-0201",  "desc": "ZooKeeper exposed. Can leak sensitive cluster configuration."},
    11211: {"service": "Memcached",  "risk": "high",   "cve": "CVE-2018-1000115","desc":"Memcached UDP amplification DDoS vector. Restrict immediately."},
}

SCAN_PORTS = list(PORT_INFO.keys()) + [
    8888, 9090, 4444, 6667, 2222, 7777, 8000, 8888, 9999, 10000
]

# ─── Helper functions ─────────────────────────────────────────────────────────
def scan_port(host, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except:
        return False

def get_banner(host, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner[:80] if banner else ""
    except:
        return ""

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = target
        return ip, hostname
    except:
        return None, None

def estimate_crack(entropy, guesses_per_sec):
    total = 2 ** entropy if entropy > 0 else 1
    secs = total / guesses_per_sec / 2
    if secs < 1:        return "Instantly"
    if secs < 60:       return f"{int(secs)} seconds"
    if secs < 3600:     return f"{int(secs/60)} minutes"
    if secs < 86400:    return f"{int(secs/3600)} hours"
    if secs < 31536000: return f"{int(secs/86400)} days"
    if secs < 3.15e9:   return f"{int(secs/31536000)} years"
    return "Centuries+"

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
@app.route('/hackshield')
def index():
    return send_from_directory('static', 'index.html')

# ─── Port Scan API ────────────────────────────────────────────────────────────
@app.route('/api/scan', methods=['POST'])
def port_scan():
    data = request.json
    target = data.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target IP or domain is required"}), 400

    ip, hostname = resolve_host(target)
    if not ip:
        return jsonify({"error": f"Cannot resolve host: {target}"}), 400

    t_start = time.time()
    open_ports = []
    lock = threading.Lock()

    def check(port):
        if scan_port(ip, port):
            info = PORT_INFO.get(port, {
                "service": "Unknown", "risk": "unknown",
                "cve": "N/A", "desc": "No known service mapping for this port."
            })
            banner = get_banner(ip, port)
            with lock:
                open_ports.append({
                    "port": port,
                    "service": info["service"],
                    "risk": info["risk"],
                    "cve": info["cve"],
                    "desc": info["desc"],
                    "banner": banner
                })

    threads = []
    for port in set(SCAN_PORTS):
        t = threading.Thread(target=check, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    duration = round(time.time() - t_start, 2)
    open_ports.sort(key=lambda x: x["port"])

    is_private = (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.16.") or
        ip == "127.0.0.1"
    )

    return jsonify({
        "ip": ip,
        "hostname": hostname,
        "target": target,
        "network_type": "Private LAN" if is_private else "Public Internet",
        "duration": duration,
        "open_ports": open_ports,
        "stats": {
            "total": len(open_ports),
            "high": sum(1 for p in open_ports if p["risk"] == "high"),
            "medium": sum(1 for p in open_ports if p["risk"] == "medium"),
            "low": sum(1 for p in open_ports if p["risk"] == "low"),
        }
    })

# ─── Password Audit API ───────────────────────────────────────────────────────
@app.route('/api/password', methods=['POST'])
def check_password():
    data = request.json
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "Password is required"}), 400

    checks = {
        "length":    len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digit":     bool(re.search(r'\d', password)),
        "symbol":    bool(re.search(r'[^A-Za-z0-9]', password)),
        "long":      len(password) >= 12,
        "very_long": len(password) >= 16,
    }

    charset = 0
    if checks["lowercase"]: charset += 26
    if checks["uppercase"]: charset += 26
    if checks["digit"]:     charset += 10
    if checks["symbol"]:    charset += 32
    entropy = round(len(password) * math.log2(charset), 1) if charset else 0

    score = sum([
        checks["length"], checks["uppercase"], checks["lowercase"],
        checks["digit"], checks["symbol"], checks["long"], checks["very_long"],
    ])

    if score <= 2:   strength = "Very Weak"
    elif score <= 3: strength = "Weak"
    elif score == 4: strength = "Fair"
    elif score == 5: strength = "Good"
    elif score == 6: strength = "Strong"
    else:            strength = "Very Strong"

    pwned_count = 0
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        for line in r.text.splitlines():
            h, count = line.split(':')
            if h == suffix:
                pwned_count = int(count)
                break
    except:
        pwned_count = -1

    crack_times = {
        "online_throttled":   estimate_crack(entropy, 100),
        "online_unthrottled": estimate_crack(entropy, 10000),
        "offline_fast":       estimate_crack(entropy, 1e10),
        "offline_gpu":        estimate_crack(entropy, 1e13),
    }

    return jsonify({
        "strength": strength,
        "score": score,
        "max_score": 7,
        "entropy": entropy,
        "length": len(password),
        "checks": checks,
        "pwned": pwned_count,
        "crack_times": crack_times,
    })

# ─── SSL Checker API ─────────────────────────────────────────────────────────
@app.route('/api/ssl', methods=['POST'])
def ssl_check():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(6)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        cipher = conn.cipher()
        tls_version = conn.version()
        conn.close()

        expire_str = cert['notAfter']
        expire_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
        today = datetime.datetime.utcnow()
        days_left = (expire_date - today).days

        subject = dict(x[0] for x in cert['subject'])
        issuer  = dict(x[0] for x in cert['issuer'])
        issued_to = subject.get('commonName', domain)
        issued_by = issuer.get('organizationName', 'Unknown')
        valid_from = cert['notBefore']

        san_list = []
        for item in cert.get('subjectAltName', []):
            if item[0] == 'DNS':
                san_list.append(item[1])

        WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON', 'ADH', 'AECDH']
        cipher_name = cipher[0] if cipher else 'Unknown'
        is_weak_cipher = any(w in cipher_name.upper() for w in WEAK_CIPHERS)

        WEAK_TLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        is_weak_tls = tls_version in WEAK_TLS

        issues = []
        if days_left < 0:
            issues.append({"issue": "Certificate is EXPIRED", "risk": "high"})
        elif days_left < 15:
            issues.append({"issue": f"Expires very soon — only {days_left} days left", "risk": "high"})
        elif days_left < 30:
            issues.append({"issue": f"Expiring soon — {days_left} days left", "risk": "medium"})

        if is_weak_cipher:
            issues.append({"issue": f"Weak cipher detected: {cipher_name}", "risk": "high"})
        if is_weak_tls:
            issues.append({"issue": f"Outdated TLS version in use: {tls_version}", "risk": "high"})
        if not san_list:
            issues.append({"issue": "No Subject Alternative Names (SAN) found", "risk": "medium"})

        if any(i['risk'] == 'high' for i in issues):
            grade = 'F'
        elif any(i['risk'] == 'medium' for i in issues):
            grade = 'C'
        elif days_left < 60:
            grade = 'B'
        else:
            grade = 'A'

        return jsonify({
            "domain": domain,
            "issued_to": issued_to,
            "issued_by": issued_by,
            "valid_from": valid_from,
            "valid_until": expire_str,
            "days_left": days_left,
            "tls_version": tls_version,
            "cipher": cipher_name,
            "cipher_bits": cipher[2] if cipher else 0,
            "san": san_list[:10],
            "is_weak_cipher": is_weak_cipher,
            "is_weak_tls": is_weak_tls,
            "issues": issues,
            "grade": grade,
            "status": "valid" if days_left > 0 else "expired"
        })

    except ssl.SSLCertVerificationError as e:
        return jsonify({"error": f"SSL verification failed: {str(e)}", "grade": "F"})
    except socket.timeout:
        return jsonify({"error": "Connection timed out — check domain name"}), 408
    except ConnectionRefusedError:
        return jsonify({"error": "Port 443 not open — domain may not support HTTPS"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── GeoIP API ────────────────────────────────────────────────────────────────
@app.route('/api/geoip', methods=['POST'])
def geoip():
    data = request.json
    ip = data.get('ip', '').strip()
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        d = r.json()
        return jsonify({
            "city":      d.get("city", "Unknown"),
            "region":    d.get("region", "Unknown"),
            "country":   d.get("country_name", "Unknown"),
            "org":       d.get("org", "Unknown"),
            "timezone":  d.get("timezone", "Unknown"),
            "latitude":  d.get("latitude"),
            "longitude": d.get("longitude"),
        })
    except:
        return jsonify({"error": "GeoIP lookup failed"}), 500

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("\n" + "="*50)
    print("  HackShield Dashboard — Backend Running")
    print("  Open: http://localhost:5000/hackshield")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)