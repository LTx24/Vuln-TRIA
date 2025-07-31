# Vuln-TRIA: AI-Powered Vulnerability Triage & Remediation Dashboard

Vuln-TRIA is a modern web application that enables **AI-powered security scanning** and instant risk remediation guidance for any web address or IP. Designed for clarity, speed, and practical results, this dashboard is perfect for security students, researchers, or anyone seeking one-click network and web vulnerability insight.

---

## 💡 What This Project Does

- **Performs Vulnerability Scanning:** Every scan (triggered by entering a target and submitting) analyzes the live network or website for vulnerabilities, using a machine learning model (Random Forest) or connects to a real scanner engine (like ZAP, if integrated).
- **Automatic Risk Assessment:** Scan results are categorized into Critical, High, Medium, or Low risk. The triage status color and main message reflect the highest risk found in the scan.
- **Real, Practical Remediation:** For every scan, you receive tailored, actionable steps for actual remediation—matched to the vulnerabilities and risk class detected.
- **Instant UI Feedback:** Results and historical scans display in a beautiful, color-coded, and responsive dashboard interface—no refresh or external reports needed.
- **History Log:** Every scan is saved (with date, time, risk, and remediation guidance) and visible in a "Scan History Log" to help track progress and risk trends.

---

## 🚀 How It Works (User & Technical Flow)

**User Workflow:**
1. **Open the app** on your computer (`http://127.0.0.1:5000`).
2. **Enter a target site or IP** (e.g., `https://example.com`).
3. **Click "Start AI Scan."**
4. Instantly see:
   - Color-coded results and risk status (Critical/High/Medium/Low/All clear)
   - Details about open ports/services/risk (if present)
   - Human-friendly remediation steps to fix or mitigate issues
   - The scan is saved in a history log for later reference

**Technical Stack & Features:**
- **Flask Web App** with Bootstrap for a modern front end (Python).
- **dashboard.html** and `style.css` power a highly readable, mobile-friendly UI.
- **AI Model:** Uses Random Forest (via scikit-learn) to triage results (simple version); can integrate with real-world scanners (like ZAP) for richer findings.
- **Data & History:** Scan details and risk summaries are stored in a local SQLite database for instant and persistent access.
- **Easy Setup:** All dependencies listed in `requirements.txt`; project is isolated by a self-created Python virtual environment.
- **Runs on Windows in 1 step:** A PowerShell script (`start.ps1`) automates environment setup and launch.

---

## 🚀 Screenshots

### Dashboard Home
<img width="1893" height="641" alt="brave_screenshot" src="https://github.com/user-attachments/assets/f358228e-00b7-4d8a-a015-fad0c7839fbb" />

### Scan History Log
<img width="1686" height="713" alt="brave_screenshot (2)" src="https://github.com/user-attachments/assets/b96b02a8-7b82-4854-aabc-39cb5db8304c" />

### High-Risk Finding
<img width="1912" height="965" alt="brave_screenshot (4)" src="https://github.com/user-attachments/assets/a6236353-d6c6-4738-ae64-416ef49515bd" />

### Low-Risk Finding
<img width="1915" height="951" alt="brave_screenshot (1)" src="https://github.com/user-attachments/assets/6bde9221-12c7-46a0-a752-6af7d554af0f" />

## 🖥️ How to Run This Project (Windows, Powershell)

### 1. Clone the repository

git clone https://github.com/LTx24e/vuln-tria.git
cd vuln-tria


### 2. Start the project with one command

.\start.ps1

- If you see a permissions error, run:  
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`  
  and then try `.\start.ps1` again.

The script will:
- Create and activate a virtual environment if not present
- Install all requirements
- Launch the AI dashboard server

### 3. Access the dashboard

- Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.


## ✨ Features

- **AI-powered triage of every scan**: Only the advanced/ML scan path is offered.
- **Visual Severity:** Results highlighted with green, blue, or red banners for Low/Medium/Critical.
- **Remediation Guidance:** For each risk level, users get clear, actionable, jargon-free advice.
- **Responsive design and scan log history:** Dashboard looks great on desktop or mobile.
- **No scan-type confusion:** The workflow is always "AI," no dropdown or basic/legacy scan code clutter.
- **Simple local setup:** Clone, run the script, and you're ready—no manual dependency wrangling.

---

## 🛠️ How To Use

1. **Enter a domain or IP** in the input (homepage).
2. **Hit "Start AI Scan."**
3. Inspect the results and read the steps given under "Practical Remediation."
4. View and monitor previous scans in the Scan History Log.
5. Use "Clear Results" to reset the scan view.

---

## 👨‍💻 Developer Notes

- **Requirements:** All libraries are managed in `requirements.txt`.
- **Database:** Uses SQLite (`scans.db`). Auto-created if missing.
- **.gitignore:** Excludes venv, database files, and Python cache folders.
- **Customize further:** Integrate OWASP ZAP, Burp Suite, or other APIs for even deeper findings!

---

## 📝 License

MIT License 

---

## ✍️ Author

Lakshya Thakur
https://github.com/LTx24

---

*Enjoy, share, and open issues or PRs for improvements!*

---
