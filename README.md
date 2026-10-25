# Unified Threat Intelligence, Hunting & Incident Response Platform

A Python-based cybersecurity lab that combines **IOC analysis, threat hunting, and Wazuh SIEM alerting** using synthetic training data.

> **Project status:** Learning and portfolio project. All included event data is simulated and does not represent a confirmed real-world attack.

## Objectives

- Validate and analyze Indicators of Compromise (IOCs).
- Hunt for suspicious authentication patterns in simulated Windows events.
- Export detection results as JSON for Wazuh SIEM.
- Create and validate a custom Wazuh detection rule.
- Produce reports and evidence for investigation and documentation.

## Architecture

1. **IOC Analysis:** Validate indicators and compare them against a local training feed.
2. **Threat Hunting:** Analyze simulated Windows logon events and flag repeated failures.
3. **Event Export:** Convert hunting findings into JSON events.
4. **SIEM Integration:** Ingest the events into Wazuh and generate an alert.
5. **Reporting:** Save CSV analysis reports and JSON alert evidence.

## Technology Stack

- Python 3
- CSV and JSON processing
- Wazuh SIEM
- Linux / Kali Linux
- Git and GitHub
- MITRE ATT&CK

## Module 1: IOC Analysis Engine

### Features

- Validates IP addresses, domains, URLs, and file hashes.
- Identifies duplicate indicators.
- Matches indicators against a local synthetic training feed.
- Records assessment and related indicator details.
- Generates a CSV analysis report.

### Run

From the project root:

```bash
source venv/bin/activate
python src/ioc_analyzer.py
```

### Output

`reports/ioc_analysis.csv`

**Limitation:** Matching against a local training feed is not the same as checking live threat intelligence or proving an indicator is malicious.

## Module 2: Threat Hunting

### Data source

`sample_data/windows_events.csv`

The dataset uses simulated Windows Security event IDs:

- **4625:** Failed logon
- **4624:** Successful logon

### Detection logic

- Groups failed logons by username and source IP address.
- Flags five or more failed logons for investigation.
- Maps the behavior to MITRE ATT&CK **T1110 — Brute Force** as a candidate technique.

### Run

```bash
python src/threat_hunter.py
```

### Output

`reports/threat_hunting_report.csv`

**Investigation note:** Repeated failed logons alone do not establish a brute-force attack. Analysts should examine timestamps, source context, successful logons, and other supporting evidence.

## Module 3: Wazuh SIEM Integration

### Implementation

- Exports threat-hunting findings to JSON.
- Configures Wazuh to monitor the JSON event file.
- Adds custom Wazuh rule **100100** for the simulated `POSSIBLE_PASSWORD_GUESSING` event.
- Validates rule matching and confirms the generated alert in the Wazuh dashboard.
- Saves an example alert as evidence.

### Run the event exporter

```bash
python src/export_wazuh_event.py
```

### Related files

- `wazuh-integration/wazuh_events.json`
- `reports/wazuh_events.json`
- `reports/wazuh-alert-evidence.json`

**MITRE ATT&CK mapping:** T1110 — Brute Force. This is a candidate behavioral mapping for the simulated event, not proof of an actual attack.

## Project Structure

```text
Threat-Lab/
├── README.md
├── .gitignore
├── src/
│   ├── ioc_analyzer.py
│   ├── threat_hunter.py
│   └── export_wazuh_event.py
├── sample_data/
│   ├── iocs.csv
│   ├── threat_feed.csv
│   └── windows_events.csv
├── reports/
│   ├── ioc_analysis.csv
│   ├── threat_hunting_report.csv
│   ├── wazuh_events.json
│   └── wazuh-alert-evidence.json
└── wazuh-integration/
    └── wazuh_events.json
```

## Skills Demonstrated

- Python scripting and data processing
- IOC validation and local-feed matching
- Authentication-event analysis
- Basic detection engineering
- JSON event integration with a SIEM
- Custom Wazuh rule testing
- MITRE ATT&CK mapping
- Investigation documentation and Git version control

## Limitations and Future Improvements

- The current datasets are synthetic, not live endpoint telemetry.
- IOC reputation checks use a local training feed rather than a live intelligence service.
- The password-guessing detection is a simple threshold-based rule and may produce false positives.
- Future improvements could include richer event correlation, configurable thresholds, automated tests, dashboard screenshots, and integration with a trusted threat-intelligence source.

## Disclaimer

This project is for education, authorized testing, and portfolio demonstration. Its sample indicators and events must not be treated as confirmed malicious activity.

