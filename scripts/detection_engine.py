import requests
import json
from datetime import datetime, timezone, timedelta
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from slack_notifier import send_alert as slack_alert
from virustotal_checker import run_vt_check, create_vt_index

ES_URL= os.environ.get("ES_URL", "http://localhost:9200")
INDEX= "soc-macos-logs"
ALERTS_INDEX= "soc-alerts"

WHITELIST_PROCESSES= [
    "biomesyncd", "biomed", "tccd", "launchd", "Safari",
    "com.apple.Safari.SafeBrowsing.Service",
    "com.apple.WebKit.Networking", "secd", "trustd",
    "translationd", "deleted"
]

RULES= {
    "brute_force_auth": {
        "description": "Multiple login failures - possible brute-force attack",
        "phrases":     ["authentication failed", "login incorrect", "invalid credentials", "auth failure"],
        "exclude_processes": WHITELIST_PROCESSES,
        "threshold":   5,
        "window_min":  2,
        "severity":    "HIGH",
    },
    "network_scan": {
        "description": "Serial call refusals - possible port scan",
        "phrases":     ["connection refused", "connection reset by peer", "no route to host"],
        "exclude_processes": ["Safari", "com.apple.WebKit.Networking", "nsurlsessiond"],
        "threshold":   15,
        "window_min":  2,
        "severity":    "MEDIUM",
    },
    "privilege_escalation": {
        "description": "Attempted privilege escalation outside the sandbox",
        "phrases":     ["operation not permitted", "must be run as root", "sudo: auth"],
        "exclude_processes": WHITELIST_PROCESSES,
        "threshold":   3,
        "window_min":  5,
        "severity":    "HIGH",
    },
    "suspicious_process": {
        "description": "Suspected offensive or reconnaissance tool",
        "phrases":     ["nmap ", "netcat ", "/bin/nc ", "base64 --decode", "curl | bash", "wget | sh"],
        "exclude_processes": [],
        "threshold":   1,
        "window_min":  10,
        "severity":    "CRITICAL",
    },
    "credential_access": {
        "description": "Access to credentials or keychain",
        "phrases":     ["keychain unlock failed", "SecKeychainFind", "kSecClass", "certificate verify failed"],
        "exclude_processes": ["trustd", "secd"],
        "threshold":   3,
        "window_min":  5,
        "severity":    "HIGH",
    },
    "defense_evasion": {
    "description": "Attempting to cover up the tracks – history modification or obfuscation",
    "phrases":     ["base64 --decode", "history -c", "rm .bash_history",
                    "chmod 777", "chflags hidden"],
    "exclude_processes": [],
    "threshold":   1,
    "window_min":  5,
    "severity":    "HIGH",
},
}

def create_alerts_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp":       {"type": "date"},
                "rule":            {"type": "keyword"},
                "severity":        {"type": "keyword"},
                "description":     {"type": "keyword"},
                "count":           {"type": "integer"},
                "window_min":      {"type": "integer"},
                "sample_messages": {"type": "text"},
            }
        }
    }
    r= requests.put(f"{ES_URL}/{ALERTS_INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"Alerts index '{ALERTS_INDEX}' ready")

def query_logs(phrases, exclude_processes, window_minutes):
    since= (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    should_clauses= [{"match_phrase": {"message": phrase}} for phrase in phrases]
    must_not_clauses= [{"term": {"process": proc}} for proc in exclude_processes]

    query= {
        "query": {
            "bool": {
                "must": [{"range": {"timestamp": {"gte": since}}}],
                "should": should_clauses,
                "minimum_should_match": 1,
                "must_not": must_not_clauses
            }
        },
        "size": 5,
        "_source": ["timestamp", "message", "process", "subsystem"]
    }

    r= requests.post(f"{ES_URL}/{INDEX}/_search", json=query)
    if r.status_code != 200:
        return 0, []

    data= r.json()
    hits= data.get("hits", {})
    total= hits.get("total", {}).get("value", 0)
    samples= [
        f"[{h['_source'].get('process','?')}] {h['_source'].get('message','')[:100]}"
        for h in hits.get("hits", [])
    ]
    return total, samples

def save_alert_to_es(rule_name, rule, count, samples):
    alert= {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "rule":            rule_name,
        "severity":        rule["severity"],
        "description":     rule["description"],
        "count":           count,
        "window_min":      rule["window_min"],
        "sample_messages": " | ".join(samples[:3])
    }
    r= requests.post(f"{ES_URL}/{ALERTS_INDEX}/_doc", json=alert)
    return r.status_code == 201

def run_detection():
    print(f"\nDetection cycle — {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'Rule':<28} {'Events':>6}  {'Window':>6}  Status")
    print(f"{'-'*28} {'-'*6}  {'-'*6}  {'-'*30}")

    alerts_fired= 0
    network_scan_triggered= False

    for rule_name, rule in RULES.items():
        count, samples= query_logs(
            rule["phrases"],
            rule["exclude_processes"],
            rule["window_min"]
        )

        if count >= rule["threshold"]:
            save_alert_to_es(rule_name, rule, count, samples)

            # Slack alert
            slack_alert(
                rule_name=rule_name,
                severity=rule["severity"],
                description=rule["description"],
                count=count,
                window_min=rule["window_min"],
                samples=samples
            )

            status= f"ALERT [{rule['severity']}] -> Slack"
            alerts_fired += 1

            if rule_name == "network_scan":
                network_scan_triggered = True

            for s in samples[:2]:
                print(f"{'':28}   {s[:70]}")
        else:
            status = f"OK  [{rule['severity']}]"

        print(f"  {rule_name:<28} {count:>6}  {rule['window_min']:>4}min  {status}")

    if network_scan_triggered:
        print(f"\nnetwork_scan triggered — running VirusTotal check")
        run_vt_check(window_minutes=5)

    print(f"\nAlerts fired: {alerts_fired}")
    return alerts_fired

def run():
    print("SOC Lab — Detection Engine")
    create_alerts_index()
    create_vt_index()
    print(f"Loaded {len(RULES)} rules\n")

    while True:
        run_detection()
        next_run= (datetime.now() + timedelta(seconds=60)).strftime('%H:%M:%S')
        print(f"\nNext cycle: {next_run} | Ctrl+C to stop")
        time.sleep(60)

if __name__ == "__main__":
    run()