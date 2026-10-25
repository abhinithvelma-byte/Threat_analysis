import csv
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "sample_data" / "windows_events.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "threat_hunting_report.csv"

THRESHOLD = 5


def main():
    failed_logins = Counter()
    total_events = 0

    with INPUT_FILE.open(newline="", encoding="utf-8") as file:
        for event in csv.DictReader(file):
            total_events += 1

            if event["event_id"].strip() == "4625":
                key = (
                    event["username"].strip(),
                    event["source_ip"].strip(),
                )
                failed_logins[key] += 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        fields = [
            "username",
            "source_ip",
            "failed_attempts",
            "detection",
            "assessment",
            "mitre_technique"
        ]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for (username, source_ip), count in failed_logins.items():
            detected = count >= THRESHOLD
            writer.writerow({
                "username": username,
                "source_ip": source_ip,
                "failed_attempts": count,
                "detection": (
                    "POSSIBLE_PASSWORD_GUESSING"
                    if detected else "Below threshold"
                ),
                "assessment": (
                    "Simulated training data; investigate before concluding"
                ),
                "mitre_technique": (
                    "T1110 - Brute Force (candidate mapping; validate evidence)"
                ),
            })

    print(f"Events analyzed: {total_events}")
    print(f"User/source pairs with failed logins: {len(failed_logins)}")
    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
