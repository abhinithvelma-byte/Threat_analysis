# Unified Threat Intelligence, Hunting & Incident Response Platform

## Module 1: IOC Analysis Engine

### Objective
Build a Python-based engine to validate and analyze Indicators of Compromise (IOCs).

### Features
- Validates IP addresses, domains, URLs, and file hashes.
- Detects duplicate indicators.
- Matches indicators against a local training feed.
- Records reputation, confidence, and assessment fields.
- Generates a CSV analysis report.

### Technologies
- Python 3
- CSV data handling
- Local threat-intelligence feed
- Git and GitHub

### Run
```bash
source venv/bin/activate
python src/ioc_analyzer.py


## Threat Hunting Module

### Objective
Analyze simulated Windows security events to identify repeated failed logon attempts.

### Data Source
- `sample_data/windows_events.csv`
- Windows Event ID 4625: failed logon
- Windows Event ID 4624: successful logon

### Detection Logic
- Groups failed logons by username and source IP address.
- Uses a threshold of five failed logons to flag a possible password-guessing pattern.
- Maps the pattern to MITRE ATT&CK T1110 — Brute Force as a candidate technique for further investigation.

### Output
- `reports/threat_hunting_report.csv`

### Limitations
- The events are simulated training data, not real production logs.
- Repeated failed logons alone do not prove a brute-force attack.
- Analysts should review timestamps, source context, successful logons, and other evidence before drawing conclusions.
## Wazuh SIEM Integration

- Integrated Threat-Lab detection output with Wazuh SIEM.
- Exported simulated threat-hunting detections as JSON events.
- Configured Wazuh to monitor the event file.
- Created custom Wazuh rule 100100 to detect possible password guessing.
- Verified the generated alert in the Wazuh dashboard.
- Mapped the detection to MITRE ATT&CK T1110 (Brute Force).

Note: This project uses synthetic training data. Alerts are
demonstrations for learning and do not establish a real attack.
