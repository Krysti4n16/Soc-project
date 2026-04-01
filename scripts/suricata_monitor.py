import json
import requests
import os
import time
from datetime import datetime, timezone
import sys

sys.path.insert(0, os.path.dirname(__file__))
from slack_notifier import send_alert as slack_alert

ES_URL= "http://localhost:9200"
SURICATA_INDEX= "soc-suricata"

LOG_FILE= os.path.expanduser("~/Desktop/soc-project/suricata/logs/eve.json")

def create_suricata_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp":   {"type": "date"},
                "event_type":  {"type": "keyword"},
                "src_ip":      {"type": "keyword"},
                "dest_ip":     {"type": "keyword"},
                "src_port":    {"type": "integer"},
                "dest_port":   {"type": "integer"},
                "proto":       {"type": "keyword"},
                "severity":    {"type": "integer"},
                "signature":   {"type": "text"},
                "category":    {"type": "keyword"},
                "action":      {"type": "keyword"},
            }
        }
    }
    r= requests.put(f"{ES_URL}/{SURICATA_INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"Suricata index '{SURICATA_INDEX}' ready")

def parse_event(line):
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None

def save_to_es(doc):
    r= requests.post(f"{ES_URL}/{SURICATA_INDEX}/_doc", json=doc)
    return r.status_code == 201

def process_alert(event):
    alert= event.get("alert", {})
    severity= alert.get("severity", 3)

    severity_map= {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
    severity_label= severity_map.get(severity, "LOW")

    doc= {
        "timestamp":  event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "event_type": "alert",
        "src_ip":     event.get("src_ip", ""),
        "dest_ip":    event.get("dest_ip", ""),
        "src_port":   event.get("src_port", 0),
        "dest_port":  event.get("dest_port", 0),
        "proto":      event.get("proto", ""),
        "severity":   severity,
        "signature":  alert.get("signature", ""),
        "category":   alert.get("category", ""),
        "action":     alert.get("action", ""),
    }

    save_to_es(doc)

    if severity <= 2:
        slack_alert(
            rule_name=f"suricata_{alert.get('category', 'unknown').lower().replace(' ', '_')}",
            severity=severity_label,
            description=alert.get("signature", "Unknown signature"),
            count=1,
            window_min=0,
            samples=[f"{event.get('src_ip')} → {event.get('dest_ip')}:{event.get('dest_port')}"]
        )

    return severity_label, alert.get("signature", "")

def tail_log(filepath):
    try:
        with open(filepath, "r") as f:
            f.seek(0, 2)  
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.5)
    except FileNotFoundError:
        print(f"Log file not found: {filepath}")
        print(f"Ensure Suricata is running: sudo suricata -c ~/Desktop/soc-project/suricata/suricata.yaml -i en0")
        return

def run():
    print("SOC Lab — Suricata IDS Monitor")
    create_suricata_index()
    print(f"Watching: {LOG_FILE}")
    print("Waiting for Suricata alerts\n")

    alerts= 0
    for line in tail_log(LOG_FILE):
        event= parse_event(line)
        if not event:
            continue

        event_type= event.get("event_type", "")

        if event_type == "alert":
            severity_label, signature = process_alert(event)
            alerts += 1
            ts= datetime.now().strftime("%H:%M:%S")
            src= event.get("src_ip", "?")
            dst= f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
            print(f"[{ts}] [{severity_label}] {src} → {dst}")
            print(f"         {signature[:80]}")

        elif event_type == "dns":
            query = event.get("dns", {}).get("rrname", "")
            if any(kw in query for kw in [".onion", ".xyz", ".top", ".ru"]):
                ts= datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] [DNS] Suspicious query: {query}")

if __name__ == "__main__":
    run()