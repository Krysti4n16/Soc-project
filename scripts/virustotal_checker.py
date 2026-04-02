import requests
import json
import os
import re
import time
from datetime import datetime, timezone

ES_URL= os.environ.get("ES_URL", "http://localhost:9200")
VT_INDEX= "soc-virustotal"

def get_api_key():
    key= os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        try:
            with open(os.path.join(os.path.dirname(__file__), "../.env")) as f:
                for line in f:
                    if line.startswith("VIRUSTOTAL_API_KEY="):
                        key = line.strip().split("=", 1)[1]
        except FileNotFoundError:
            pass
    return key

def create_vt_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp":      {"type": "date"},
                "ip":             {"type": "keyword"},
                "malicious":      {"type": "integer"},
                "suspicious":     {"type": "integer"},
                "harmless":       {"type": "integer"},
                "verdict":        {"type": "keyword"},
                "country":        {"type": "keyword"},
                "as_owner":       {"type": "keyword"},
                "threat_names":   {"type": "keyword"},
                "vt_link":        {"type": "keyword"},
            }
        }
    }
    r= requests.put(f"{ES_URL}/{VT_INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"VirusTotal index '{VT_INDEX}' ready")

def extract_ips_from_logs(window_minutes=30):
    import subprocess

    private= re.compile(
        r'^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|0\.|169\.254\.|::1|fe80)'
    )

    try:
        result= subprocess.run(
            ["netstat", "-n", "-p", "tcp"],
            capture_output=True, text=True
        )
        ips= set()
        for line in result.stdout.splitlines():
            parts= line.split()
            if len(parts) < 5:
                continue
            if parts[5] not in ("ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT"):
                continue
            foreign= parts[4]
            ip= foreign.rsplit(".", 1)[0]
            if not private.match(ip):
                parts_ip= ip.split(".")
                if len(parts_ip) == 4:
                    try:
                        if all(0 <= int(p) <= 255 for p in parts_ip):
                            ips.add(ip)
                    except ValueError:
                        continue
        return list(ips)

    except Exception as e:
        print(f"netstat error: {e}")
        return []

def check_ip_virustotal(ip, api_key):
    headers= {"x-apikey": api_key}
    url= f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:
        r= requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return None
        else:
            print(f"VT API error {r.status_code} for {ip}")
            return None
    except requests.RequestException as e:
        print(f"Request failed for {ip}: {e}")
        return None

def parse_vt_response(ip, data):
    attrs= data.get("data", {}).get("attributes", {})
    stats= attrs.get("last_analysis_stats", {})
    threat_names= list(set(
        v.get("result", "")
        for v in attrs.get("last_analysis_results", {}).values()
        if v.get("category") == "malicious" and v.get("result")
    ))[:5]

    malicious= stats.get("malicious", 0)
    suspicious= stats.get("suspicious", 0)

    if malicious >= 5:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "ip":           ip,
        "malicious":    malicious,
        "suspicious":   suspicious,
        "harmless":     stats.get("harmless", 0),
        "verdict":      verdict,
        "country":      attrs.get("country", "unknown"),
        "as_owner":     attrs.get("as_owner", "unknown"),
        "threat_names": threat_names,
        "vt_link":      f"https://www.virustotal.com/gui/ip-address/{ip}",
    }

def save_to_es(doc):
    r= requests.post(f"{ES_URL}/{VT_INDEX}/_doc", json=doc)
    return r.status_code == 201

def already_checked_today(ip):
    query= {
        "query": {
            "bool": {
                "must": [
                    {"term": {"ip": ip}},
                    {"range": {"timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        "size": 1
    }
    r= requests.post(f"{ES_URL}/{VT_INDEX}/_search", json=query)
    if r.status_code == 200:
        return r.json().get("hits", {}).get("total", {}).get("value", 0) > 0
    return False

def run_vt_check(window_minutes=10):
    api_key= get_api_key()
    if not api_key:
        print("No VIRUSTOTAL_API_KEY in .env")
        return

    print(f"\nVirusTotal check — {datetime.now().strftime('%H:%M:%S')}")
    ips= extract_ips_from_logs(window_minutes)

    if not ips:
        print("No external IPs found in recent logs")
        return

    print(f"Found {len(ips)} unique external IPs")
    checked= 0
    threats= 0

    for ip in ips:
        if already_checked_today(ip):
            print(f"{ip:<18} skipped (checked today)")
            continue

        data= check_ip_virustotal(ip, api_key)
        if not data:
            continue

        doc= parse_vt_response(ip, data)
        save_to_es(doc)
        checked += 1

        verdict_label= {
            "MALICIOUS":  "*** MALICIOUS ***",
            "SUSPICIOUS": "  ~ suspicious ~",
            "CLEAN":      "  ok"
        }.get(doc["verdict"], "unknown")

        print(f"{ip:<18} [{doc['country']}] {doc['as_owner'][:30]:<30} {verdict_label}")
        if doc["threat_names"]:
            print(f"  {'':18}   Threats: {', '.join(doc['threat_names'])}")

        if doc["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            threats += 1

        time.sleep(15)

    print(f"\nChecked: {checked} IPs | Threats found: {threats}")

if __name__ == "__main__":
    create_vt_index()
    run_vt_check(window_minutes=30)