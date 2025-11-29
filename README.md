# Mini SIEM Detection Rules

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A minimal learning project that pairs **Sigma-style detection rules** with sample JSON logs and a lightweight rule engine. Built for anyone wanting hands-on experience with how SIEM detections work—no external dependencies required.

## 📁 Project Structure

```
mini-siem-detection-rules/
├── rules/                          # Sigma-style YAML detection rules
│   ├── auth_bruteforce.yml
│   ├── windows_suspicious_powershell.yml
│   ├── linux_privilege_escalation.yml
│   └── web_sql_injection.yml
├── logs/                           # Sample JSON log files
│   ├── sample_windows_security_logs.json
│   ├── sample_linux_auth_logs.json
│   └── sample_web_access_logs.json
├── engine/                         # Detection engine package
│   ├── __init__.py
│   └── mini_sigma_engine.py
├── run_all_rules.py                # Batch rule execution helper
├── README.md
└── LICENSE
```

## ✨ Features

- **4 Sigma-style rules** covering common attack scenarios:
  - Authentication brute-force attempts
  - Suspicious PowerShell execution (encoded commands, download cradles)
  - Linux privilege escalation via sudo/su
  - SQL injection in web server logs
- **Sample log files** with both matching events and false-positive examples
- **Lightweight Python engine** using only the standard library
- **Batch execution script** to run all rules against a log file

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/mini-siem-detection-rules.git
cd mini-siem-detection-rules

# No dependencies to install - uses Python standard library only
# Requires Python 3.8+
python --version
```

## 📖 Usage

### Run a single rule

```bash
python engine/mini_sigma_engine.py \
    --logs logs/sample_windows_security_logs.json \
    --rule rules/windows_suspicious_powershell.yml
```

**Example output:**
```
Matched rule 'Suspicious PowerShell Execution' on event: user=svc_security, process_name=powershell.exe
Matched rule 'Suspicious PowerShell Execution' on event: user=svc_security, process_name=powershell.exe
...
5 events matched rule 'Suspicious PowerShell Execution'
```

### Run all rules against a log file

```bash
python run_all_rules.py \
    --logs logs/sample_linux_auth_logs.json \
    --rules-dir rules
```

**Example output:**
```
============================================================
RULE EXECUTION SUMMARY
============================================================
Log file: logs/sample_linux_auth_logs.json
Total events: 13
------------------------------------------------------------
[auth_bruteforce.yml] Application Authentication Brute-Force: 7 matches
[linux_privilege_escalation.yml] Linux Privilege Escalation via Sudo/Su: 3 matches
[web_sql_injection.yml] Web Server SQL Injection Attempt: no matches
[windows_suspicious_powershell.yml] Suspicious PowerShell Execution: no matches
------------------------------------------------------------
Total: 4 rules applied, 10 total matches
============================================================
```

## 📚 About Sigma

[Sigma](https://github.com/SigmaHQ/sigma) is an open-source, vendor-agnostic rule format for describing log-based detections. Rules written in Sigma can be converted to queries for various SIEM platforms (Splunk, Elastic, Microsoft Sentinel, etc.).

This project uses a **simplified subset** of the Sigma format for educational purposes.

## ⚠️ Limitations

This project is **purely educational** and not intended for production use:

- No persistence, alerting, or log enrichment
- The YAML parser handles only basic structures (no anchors, multi-line strings, etc.)
- Detection supports only `selection` blocks with exact and substring (`|contains`) matching
- No timeframe-based correlation or aggregation logic
- Not optimized for large log volumes

## 🎯 How This Relates to SOC / SIEM Work

| Concept | What This Project Demonstrates |
|---------|-------------------------------|
| **Detection Engineering** | Writing rules that map specific log fields to threat indicators |
| **Rule Tuning** | Understanding why rules match (or don't) based on field values |
| **Sigma Portability** | How vendor-neutral rule formats enable cross-platform detection |
| **Testing & Validation** | Using curated sample data to verify rule behavior before deployment |
| **Alert Triage** | Reviewing match summaries to prioritize investigation |

## 🔮 Future Ideas

- [ ] Add more rules: Windows process abuse, network IOCs, cloud audit logs
- [ ] Support regex patterns and boolean `AND`/`OR`/`NOT` conditions
- [ ] Implement timeframe-based aggregation (e.g., "5 failures in 1 minute")
- [ ] Map rules to [MITRE ATT&CK](https://attack.mitre.org/) tactics and techniques
- [ ] Build a simple web UI or Jupyter notebook for interactive exploration
- [ ] Add unit tests for the engine

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new detection rules
- Improve the engine's matching capabilities
- Submit sample log files for additional scenarios
- Fix bugs or improve documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Disclaimer:** This tool is for educational purposes only. Always follow your organization's security policies and obtain proper authorization before testing detection rules against real systems.
