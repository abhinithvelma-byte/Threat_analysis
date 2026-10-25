import csv
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "sample_data" / "iocs.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "ioc_analysis.csv"
FEED_FILE = BASE_DIR / "sample_data" / "threat_feed.csv"
HASH_PATTERNS = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
}


def classify_indicator(value):
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip", "Valid format"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]+", value):
        hash_type = HASH_PATTERNS.get(len(value))
        if hash_type:
            return "hash", f"Valid {hash_type} format"

    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        if parsed.hostname:
            return "url", "Valid URL format"
        return "url", "Invalid URL format"

    domain_pattern = (
        r"(?=^.{1,253}$)"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
    )
    if re.fullmatch(domain_pattern, value):
        return "domain", "Valid domain format"

    return "unknown", "Unrecognized format"

def lookup_threat_feed(indicator):
    if not FEED_FILE.exists():
        return "No match", "Not available"

    with FEED_FILE.open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            if row["indicator"].strip().lower() == indicator.strip().lower():
                return row["threat_label"], row["confidence"]

    return "No match", "Not available"
def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    seen = set()
    results = []

    with INPUT_FILE.open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            indicator = row["indicator"].strip()
            detected_type, status = classify_indicator(indicator)
            duplicate = indicator.lower() in seen
            seen.add(indicator.lower())

            threat_label, feed_confidence = lookup_threat_feed(indicator)
            results.append({

                "feed_match": threat_label,
                "feed_confidence": feed_confidence,
                "indicator": indicator,
                "provided_type": row["type"].strip(),
                "detected_type": detected_type,
                "source": row["source"].strip(),
                "format_status": status,
                "duplicate": duplicate,
                "reputation": "Not checked",
                "confidence": "Unassessed",
                "assessment": "Training data only; not confirmed malicious",

            })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        columns = results[0].keys() if results else [
            "indicator", "provided_type", "detected_type",
            "source", "format_status", "duplicate"
        ]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(results)

    training_matches = sum(
        1 for row in results
        if row["feed_match"] == "TRAINING_ONLY"
    )

    print(f"Indicators analyzed: {len(results)}")
    print(f"Unique indicators: {len(seen)}")
    print(f"Synthetic training-feed matches: {training_matches}")
    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

