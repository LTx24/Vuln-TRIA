import os
import sqlite3
import uuid
import time
from datetime import datetime
from flask import Flask, render_template, request
import requests

# -------------------------
# Config
# -------------------------
app = Flask(__name__)
DB_NAME = 'scans.db'
ZAP_API = os.getenv('ZAP_API', 'http://localhost:8080')
ZAP_API_KEY = os.getenv('ZAP_API_KEY', 'changeme')  # Set your actual ZAP key here

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                target TEXT,
                severity TEXT,
                remediation TEXT
            )
        ''')
        conn.commit()

init_db()

# --- Custom remediation logic for specific vulns ---
EXTRA_REMEDIES = {
    "Cross Site Scripting": [
        "Sanitize and encode all user input/output.",
        "Implement Content Security Policy (CSP) headers.",
        "Use frameworks that auto-escape.",
    ],
    "SQL Injection": [
        "Use parameterized queries or ORM.",
        "Never directly interpolate user input in SQL.",
        "Validate and sanitize all database inputs."
    ],
    "Outdated Server": [
        "Upgrade your web server to the latest stable version.",
        "Apply all vendor patches promptly."
    ],
}

def run_zap_scan(target_url):
    """Run an active scan via ZAP. Returns findings or None if ZAP not available."""
    try:
        # Start the scan
        sresp = requests.get(f"{ZAP_API}/JSON/ascan/action/scan/", params={
            "url": target_url, "apikey": ZAP_API_KEY
        }, timeout=30)
        scan_id = sresp.json().get("scan")
        if not scan_id:
            return None  # failed to start

        # Wait for scan to finish (poll status)
        while True:
            status = requests.get(f"{ZAP_API}/JSON/ascan/view/status/", params={"scanId": scan_id}).json()['status']
            if status == '100':
                break
            time.sleep(2)

        # Fetch scan alerts (findings)
        alerts = requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params={"baseurl": target_url, "apikey": ZAP_API_KEY}).json().get("alerts", [])
        findings = []
        severities = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        max_severity = -1  # for banner

        for a in alerts:
            vtype = a.get("alert", "Unknown")
            risk = a.get("risk", "Low")
            max_severity = max(max_severity, severities.get(risk, 1))
            remediation_steps = a.get("solution", "")
            custom = EXTRA_REMEDIES.get(vtype, [])
            if custom:
                remediation_steps += " " + " ".join(["- " + step for step in custom])
            findings.append({
                "type": vtype,
                "risk": risk,
                "parameter": a.get("param", ""),
                "description": a.get("description", ""),
                "remediation": remediation_steps or "See above.",
            })

        if max_severity == 3:
            triage_status = "Critical"
        elif max_severity == 2:
            triage_status = "High"
        elif max_severity == 1:
            triage_status = "Medium"
        else:
            triage_status = "Low"
        return findings, triage_status
    except Exception as e:
        print(f"ZAP not available or error: {e}")
        return None

def fetch_all_scans():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        rows = c.fetchall()
        return [
            {"id": r[0], "timestamp": r[1], "target": r[2], "severity": r[3], "remediation": r[4]}
            for r in rows
        ]

@app.route("/", methods=["GET", "POST"])
def dashboard():
    results = None

    if request.method == "POST":
        target = request.form.get("target")
        scan_type = request.form.get("scan_type", "basic")
        findings, triage_status = None, None

        # --- Try real ZAP scan first ---
        if scan_type == "advanced":
            zap_result = run_zap_scan(target)
            if zap_result:
                findings, triage_status = zap_result
                # Real ZAP results, remediation per finding
                details = [
                    {
                        "port": "",  # web vuln; port not relevant (could parse from URL)
                        "service": f["parameter"] or "web",
                        "potential_vuln": f"{f['type']}: {f['description']}",
                        "remediation": f["remediation"],
                        "risk": f["risk"],
                    }
                    for f in findings
                ]
                remediation = "See table below for tailored steps." if details else "No major vulnerabilities found; maintain secure development and review ZAP report."
            else:
                # Fallback to simulation if ZAP not available
                triage_status = "Low"
                details = []
                remediation = "OWASP ZAP not reachable; only simulation available."
        else:
            # Simple port simulation
            if "example.com" in target or "scanme" in target:
                details = [
                    {"port": 80,  "service": "http",  "potential_vuln": "Simulated open port—check for HTTP exploits",     "remediation": "Harden HTTP service." },
                    {"port": 443, "service": "https", "potential_vuln": "Simulated open port—TLS configuration",            "remediation": "Review TLS setup." }
                ]
            elif "youtube" in target or "sports" in target:
                details = [
                    {"port": 443, "service": "https", "potential_vuln": "Simulated public site—watch for phishing",        "remediation": "User awareness and monitoring." }
                ]
            else:
                details = []

            # Simple mock triage
            triage_status = "High" if details else "Low"
            remediation = "Close unused ports, patch systems, and monitor for manipulation/phishing attempts." if details else "System secure. Regular scans advised."

        # Store to SQLite
        scan_id = str(uuid.uuid4())
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?)", (
                scan_id,
                datetime.now().isoformat(),
                target,
                triage_status,
                remediation
            ))
            conn.commit()

        message = f"Scan of {target} ({scan_type})"
        scan_data = {
            "message": message,
            "triage_status": triage_status,
            "details": details,
            "remediation": remediation,
        }

        previous_vulns = fetch_all_scans()
        return render_template("dashboard.html", data={
                "message": "Vuln-TRIA Dashboard",
                "vulnerabilities": previous_vulns,
                "no_results_message": ""
            }, results=scan_data)

    # GET: show previous scans
    previous_vulns = fetch_all_scans()
    return render_template("dashboard.html", data={
            "message": "Vuln-TRIA Dashboard",
            "vulnerabilities": previous_vulns,
            "no_results_message": "No current scan results. Run a scan to see details."
        }, results=None)

@app.route("/clear_results", methods=["POST"])
def clear_results():
    previous_vulns = fetch_all_scans()
    return render_template("dashboard.html", data={
        "message": "Vuln-TRIA Dashboard",
        "vulnerabilities": previous_vulns,
        "no_results_message": "Results cleared. Run a new scan.",
    }, results=None)

if __name__ == "__main__":
    app.run(debug=True)
