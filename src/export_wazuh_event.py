import csv
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "reports" / "threat_hunting_report.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "wazuh_events.json"

def main():
    events = []

    with INPUT_FILE.open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            if row["detection"] == "POSSIBLE_PASSWORD_GUESSING":
                events.append({
                    "event_source": "Threat-Lab",
                    "event_type": row["detection"],
                    "username": row["username"],
                    "source_ip": row["source_ip"],
                    "failed_attempts": int(row["failed_attempts"]),
                    "mitre_technique": row["mitre_technique"],
                    "assessment": row["assessment"]
                })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    print(f"Events exported: {len(events)}")
    print(f"Output file: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
