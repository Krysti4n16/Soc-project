import subprocess
import json
import requests
from datetime import datetime, timezone
import time

ES_URL= "http://localhost:9200"
INDEX= "soc-macos-logs"

def create_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "message":   {"type": "text"},
                "process":   {"type": "keyword"},
                "pid":       {"type": "integer"},
                "level":     {"type": "keyword"},
                "category":  {"type": "keyword"},
                "subsystem": {"type": "keyword"},
                "raw":       {"type": "text"}
            }
        }
    }
    r= requests.put(f"{ES_URL}/{INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"Index '{INDEX}' ready")
    else:
        print(f"Index error: {r.text}")

def parse_timestamp(raw_ts):
    if not raw_ts:
        return datetime.now(timezone.utc).isoformat()
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            return datetime.strptime(raw_ts, fmt).isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()

def fetch_macos_logs(last_seconds=60):
    cmd= [
        "log", "show",
        "--last", f"{last_seconds}s",
        "--style", "json",
        "--predicate",
        '(messageType == "Error" OR messageType == "Fault") OR '
        '(subsystem CONTAINS "network") OR '
        '(subsystem CONTAINS "security") OR '
        '(subsystem CONTAINS "authorization") OR '
        '(category CONTAINS "auth") OR '
        '(eventMessage CONTAINS "denied") OR '
        '(eventMessage CONTAINS "failed") OR '
        '(eventMessage CONTAINS "unauthorized")'
    ]
    result= subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout.strip():
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

def send_to_elasticsearch(events):
    sent= 0
    for event in events:
        doc = {
            "timestamp": parse_timestamp(event.get("timestamp", "")),
            "message":   event.get("eventMessage", ""),
            "process":   event.get("processImagePath", "").split("/")[-1],
            "pid":       event.get("processID", 0),
            "level":     event.get("messageType", "unknown"),
            "category":  event.get("category", ""),
            "subsystem": event.get("subsystem", ""),
            "raw":       json.dumps(event)
        }
        r= requests.post(f"{ES_URL}/{INDEX}/_doc", json=doc)
        if r.status_code == 201:
            sent += 1
    return sent

def run():
    print("SOC Lab — macOS Log Collector")
    print("Connecting to Elasticsearch")
    create_index()
    print("Collecting: errors, auth, network, security events")
    print("[*] Interval: 60s | Press Ctrl+C to stop\n")

    while True:
        events= fetch_macos_logs(last_seconds=60)
        ts= datetime.now().strftime("%H:%M:%S")
        if events:
            sent= send_to_elasticsearch(events)
            print(f"[{ts}] {len(events)} events collected → {sent} sent to ES")
        else:
            print(f"[{ts}] No security events in last 60s")
        time.sleep(60)

if __name__ == "__main__":
    run()