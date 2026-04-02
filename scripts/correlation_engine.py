import requests
import json
from datetime import datetime, timezone, timedelta
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from slack_notifier import send_alert as slack_alert

ES_URL= os.environ.get("ES_URL", "http://localhost:9200")
CORRELATION_INDEX= "soc-correlated-incidents"


CORRELATION_RULES= [
    {
        "name": "malware_execution_chain",
        "description": (
            "Multi-stage malware execution detected: obfuscation + "
            "file drop + outbound connection — high confidence compromise"
        ),
        "severity": "CRITICAL",
        "window_min": 5,
        "mitre": ["T1027", "T1059.004", "T1041"],
        "conditions": [
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["suspicious_process", "defense_evasion"],
                "min_count": 1,
                "label": "Obfuscation/suspicious process alert"
            },
            {
                "source": "soc-osquery",
                "field": "check",
                "values": ["suspicious_files", "modified_files"],
                "min_count": 1,
                "label": "File drop in suspicious location"
            },
        ]
    },
    {
        "name": "lateral_movement_attempt",
        "description": (
            "Lateral movement pattern: network scan followed by "
            "authentication failures — possible credential attack"
        ),
        "severity": "HIGH",
        "window_min": 10,
        "mitre": ["T1046", "T1110", "T1021"],
        "conditions": [
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["network_scan"],
                "min_count": 1,
                "label": "Network scan detected"
            },
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["brute_force_auth"],
                "min_count": 1,
                "label": "Authentication failures after scan"
            },
        ]
    },
    {
        "name": "persistence_with_privilege_escalation",
        "description": (
            "Persistence mechanism deployed alongside privilege escalation "
            "attempt — attacker establishing foothold"
        ),
        "severity": "CRITICAL",
        "window_min": 10,
        "mitre": ["T1543.001", "T1548"],
        "conditions": [
            {
                "source": "soc-osquery",
                "field": "check",
                "values": ["launch_agents"],
                "min_count": 1,
                "label": "New LaunchAgent detected"
            },
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["privilege_escalation"],
                "min_count": 1,
                "label": "Privilege escalation attempt"
            },
        ]
    },
    {
        "name": "credential_harvesting",
        "description": (
            "Credential harvesting attempt: keychain access combined "
            "with suspicious process — possible data theft"
        ),
        "severity": "CRITICAL",
        "window_min": 5,
        "mitre": ["T1555", "T1555.001", "T1059"],
        "conditions": [
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["credential_access"],
                "min_count": 1,
                "label": "Keychain access attempt"
            },
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["suspicious_process", "defense_evasion"],
                "min_count": 1,
                "label": "Suspicious process during credential access"
            },
        ]
    },
    {
        "name": "exfiltration_chain",
        "description": (
            "Data exfiltration chain: defense evasion + file access + "
            "external connection — active data theft in progress"
        ),
        "severity": "CRITICAL",
        "window_min": 5,
        "mitre": ["T1027", "T1041", "T1048"],
        "conditions": [
            {
                "source": "soc-alerts",
                "field": "rule",
                "values": ["defense_evasion"],
                "min_count": 1,
                "label": "Obfuscation before exfiltration"
            },
            {
                "source": "soc-osquery",
                "field": "check",
                "values": ["active_connections", "suspicious_connection"],
                "min_count": 1,
                "label": "External connection during evasion"
            },
        ]
    },
]


def create_correlation_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp":   {"type": "date"},
                "name":        {"type": "keyword"},
                "severity":    {"type": "keyword"},
                "description": {"type": "text"},
                "mitre":       {"type": "keyword"},
                "conditions_met": {"type": "integer"},
                "conditions_total": {"type": "integer"},
                "evidence":    {"type": "object"},
                "window_min":  {"type": "integer"},
            }
        }
    }
    r= requests.put(f"{ES_URL}/{CORRELATION_INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"Correlation index '{CORRELATION_INDEX}' ready")


def check_condition(condition, window_minutes):
    since= (
        datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    ).isoformat()

    should_clauses= [
        {"match_phrase": {condition["field"]: val}}
        for val in condition["values"]
    ]

    query= {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": since}}}
                ],
                "should": should_clauses,
                "minimum_should_match": 1
            }
        },
        "size": 3,
        "_source": [condition["field"], "timestamp", "description",
                    "severity", "check"]
    }

    r= requests.post(
        f"{ES_URL}/{condition['source']}/_search",
        json=query
    )
    if r.status_code != 200:
        return False, []

    hits= r.json().get("hits", {})
    count= hits.get("total", {}).get("value", 0)
    samples= [h["_source"] for h in hits.get("hits", [])]
    return count >= condition["min_count"], samples


def already_fired_recently(rule_name, window_minutes=30):
    since= (
        datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    ).isoformat()

    query= {
        "query": {
            "bool": {
                "must": [
                    {"term": {"name": rule_name}},
                    {"range": {"timestamp": {"gte": since}}}
                ]
            }
        },
        "size": 1
    }
    r= requests.post(
        f"{ES_URL}/{CORRELATION_INDEX}/_search",
        json=query
    )
    if r.status_code == 200:
        return r.json().get("hits", {}).get("total", {}).get("value", 0) > 0
    return False


def save_incident(rule, conditions_met, evidence):
    doc= {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "name":             rule["name"],
        "severity":         rule["severity"],
        "description":      rule["description"],
        "mitre":            rule["mitre"],
        "conditions_met":   conditions_met,
        "conditions_total": len(rule["conditions"]),
        "evidence":         evidence,
        "window_min":       rule["window_min"],
    }
    r= requests.post(f"{ES_URL}/{CORRELATION_INDEX}/_doc", json=doc)
    return r.status_code == 201


def run_correlation():
    print(f"\nCorrelation cycle — {datetime.now().strftime('%H:%M:%S')}")
    print(f"  {'Scenario':<35} {'Conditions':>10}  Status")
    print(f"  {'-'*35} {'-'*10}  {'-'*25}")

    incidents_fired= 0

    for rule in CORRELATION_RULES:
        conditions_met= 0
        evidence= {}

        for condition in rule["conditions"]:
            met, samples= check_condition(condition, rule["window_min"])
            if met:
                conditions_met += 1
                evidence[condition["label"]]= [
                    str(s)[:100] for s in samples[:2]
                ]

        total= len(rule["conditions"])
        ratio= f"{conditions_met}/{total}"

        if conditions_met == total:
            if already_fired_recently(rule["name"]):
                status= "suppressed (dedup)"
            else:
                save_incident(rule, conditions_met, evidence)

                evidence_lines= [
                    f"{label}: {samples[0][:80] if samples else 'detected'}"
                    for label, samples in evidence.items()
                ]
                slack_alert(
                    rule_name=f"CORRELATED: {rule['name']}",
                    severity=rule["severity"],
                    description=rule["description"],
                    count=conditions_met,
                    window_min=rule["window_min"],
                    samples=evidence_lines
                )

                status= f"*** INCIDENT [{rule['severity']}] -> Slack"
                incidents_fired += 1

                for label, samples in evidence.items():
                    print(f"  {'':35}   + {label[:60]}")
        else:
            status = f"partial ({ratio} conditions)"

        print(f"{rule['name']:<35} {ratio:>10}  {status}")

    print(f"\nIncidents fired: {incidents_fired}")
    return incidents_fired


def run():
    print("SOC Lab — Correlation Engine")
    print("Correlates: detection_engine + osquery + Suricata")
    create_correlation_index()
    print(f"Loaded {len(CORRELATION_RULES)} correlation scenarios\n")

    while True:
        run_correlation()
        next_run= (
            datetime.now() + timedelta(seconds=90)
        ).strftime('%H:%M:%S')
        print(f"\nNext cycle: {next_run} | Ctrl+C to stop")
        time.sleep(90)


if __name__ == "__main__":
    run()