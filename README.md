# SOC Lab — Automated Threat Detection System

A home Security Operations Center (SOC) built on macOS, designed to simulate
real-world threat detection workflows used by enterprise security teams.

The system collects macOS system logs, analyzes them with a custom detection
engine, correlates alerts with threat intelligence, and notifies via Slack —
all running locally without cloud dependencies.

---

## Architecture
```
macOS System Logs
      │
      ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Log Collector  │────▶│  Elasticsearch   │────▶│   Kibana    │
│  (Python)       │     │  (SIEM backend)  │     │  Dashboard  │
└─────────────────┘     └──────────────────┘     └─────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Detection Engine    │
                    │   6 rules             │
                    │   match_phrase query  │
                    │   process whitelisting│
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │  VirusTotal  │   │    Slack     │   │   osquery    │
   │  IP checker  │   │   Alerts     │   │   Monitor    │
   └──────────────┘   └──────────────┘   └──────────────┘
                                                │
                                                ▼
                                    ┌──────────────────┐
                                    │  Suricata IDS    │
                                    │  17 custom rules │
                                    └──────────────────┘
```

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| SIEM | Elasticsearch 8.13 + Kibana | Log storage and visualization |
| Log Collection | Python 3 + macOS `log` API | System event collection |
| Detection Engine | Python 3 + ES Query DSL | Threat detection rules |
| Threat Intel | VirusTotal API v3 | IP reputation checking |
| Alerting | Slack Incoming Webhooks | Real-time notifications |
| Endpoint Monitor | osquery | Process, port, file monitoring |
| Network IDS | Suricata 7.0 | Network traffic analysis |
| Infrastructure | Docker Desktop | ELK containerization |

---

## Detection Rules

### detection_engine.py — 6 rules

| Rule | Technique | Severity | Threshold |
|------|-----------|----------|-----------|
| brute_force_auth | T1110 — Brute Force | HIGH | 5 events / 2min |
| network_scan | T1046 — Network Service Discovery | MEDIUM | 15 events / 2min |
| privilege_escalation | T1548 — Abuse Elevation Control | HIGH | 3 events / 5min |
| suspicious_process | T1059 — Command and Scripting | CRITICAL | 1 event / 10min |
| credential_access | T1555 — Credentials from Stores | HIGH | 3 events / 5min |
| defense_evasion | T1027 — Obfuscated Files | HIGH | 1 event / 5min |

### suricata/rules/custom/custom.rules — 17 rules

| ID | Rule | Category |
|----|------|----------|
| SOC-001 | Port scan detection | Reconnaissance |
| SOC-002 | SSH port scan | Reconnaissance |
| SOC-003 | Admin service scan | Reconnaissance |
| SOC-004 | SSH brute force | Credential Access |
| SOC-005 | HTTP Basic Auth brute force | Credential Access |
| SOC-006 | Tor network communication | C2 |
| SOC-007 | C2 beaconing | C2 |
| SOC-008/009 | Suspicious User-Agent | C2 |
| SOC-010 | Large HTTP POST exfiltration | Exfiltration |
| SOC-011 | Base64 in HTTP body | Exfiltration |
| SOC-012 | DNS tunneling | Exfiltration |
| SOC-013 | URL encoded payload | Defense Evasion |
| SOC-014 | PowerShell download cradle | Execution |
| SOC-015/016 | Suspicious TLD queries | C2 |
| SOC-017 | DGA detection | C2 |

---

## Simulated Incidents

All incidents simulated using MITRE ATT&CK techniques and documented
with full analyst write-ups.

| ID | Incident | Severity | Techniques |
|----|----------|----------|-----------|
| [IR-001](docs/IR-001-discovery.md) | System Discovery | HIGH | T1057, T1049, T1082 |
| [IR-002](docs/IR-002-persistence.md) | LaunchAgent Persistence | HIGH | T1543.001, T1036 |
| [IR-003](docs/IR-003-credential-access.md) | Keychain Access Attempt | HIGH | T1555, T1555.001 |
| [IR-004](docs/IR-004-defense-evasion.md) | Base64 Obfuscation + chmod | CRITICAL | T1027, T1222, T1059.004 |
| [IR-005](docs/IR-005-exfiltration.md) | Data Exfiltration Simulation | CRITICAL | T1041, T1048, T1071.004 |

---

## Project Structure
```
soc-lab/
├── scripts/
│   ├── log_collector.py        # macOS log collection → Elasticsearch
│   ├── detection_engine.py     # Threat detection rules engine
│   ├── virustotal_checker.py   # IP reputation via VirusTotal API
│   ├── slack_notifier.py       # Slack webhook notifications
│   ├── osquery_monitor.py      # Endpoint monitoring via osquery
│   └── suricata_monitor.py     # Suricata IDS log parser
├── suricata/
│   ├── suricata.yaml           # Suricata configuration
│   └── rules/
│       └── custom/
│           └── custom.rules    # 17 custom detection rules
├── docs/
│   ├── IR-001-discovery.md
│   ├── IR-002-persistence.md
│   ├── IR-003-credential-access.md
│   ├── IR-004-defense-evasion.md
│   └── IR-005-exfiltration.md
├── Dashboards/
│   ├── Alerts_by_severity.png
│   ├── Alerts_over_time.png
│   ├── Events_by_level.png
│   ├── Soc_alerts.png
│   └── Top_processes.png
├── docker-compose.yml          # ELK Stack setup
├── .env.example                # Required environment variables
└── README.md
```

---

## Setup

### Prerequisites
- macOS 12+
- Docker Desktop
- Python 3.9+
- Homebrew

### Installation
```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/soc-lab.git
cd soc-lab

# 2. Start ELK Stack
docker compose up -d

# 3. Install Python dependencies
pip3 install requests

# 4. Install endpoint monitoring tools
brew install osquery suricata

# 5. Configure environment
cp .env.example .env
# Edit .env and add your API keys:
# VIRUSTOTAL_API_KEY=your_key
# SLACK_WEBHOOK_URL=your_webhook
```

### Running
```bash
# Terminal 1 — collect logs
python3 scripts/log_collector.py

# Terminal 2 — run detection
python3 scripts/detection_engine.py

# Terminal 3 — endpoint monitoring
python3 scripts/osquery_monitor.py

# Terminal 4 — network IDS
sudo suricata -c suricata/suricata.yaml -i en0
python3 scripts/suricata_monitor.py

# Kibana dashboard
open http://localhost:5601
```

---

## Kibana Dashboard

| Alerts by Severity | Alerts over Time |
|-------------------|-----------------|
| ![Alerts by severity](Dashboards/Alerts_by_severity.png) | ![Alerts over time](Dashboards/Alerts_over_time.png) |

| Top Processes | Events by Level |
|--------------|----------------|
| ![Top processes](Dashboards/Top_processes.png) | ![Events by level](Dashboards/Events_by_level.png) |

![SOC Alerts Table](Dashboards/Soc_alerts.png)

---

## Key Results

- Collected **130,000+** security events over project duration
- Achieved **0 false positives** on clean baseline after tuning
- Detected all **5 simulated attack scenarios** successfully
- Average detection time: **< 60 seconds** from attack to Slack alert
- Checked **9 external IPs** against VirusTotal threat intelligence
- Written **17 custom Suricata rules** covering recon, C2, exfiltration

---

## Skills Demonstrated

`SIEM` `Log Analysis` `Python` `Elasticsearch` `Threat Detection`
`MITRE ATT&CK` `Incident Response` `Threat Intelligence` `IDS/IPS`
`osquery` `Suricata` `Docker` `Slack API` `VirusTotal API`
`False Positive Tuning` `Network Security` `Endpoint Monitoring`

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elastic Documentation](https://www.elastic.co/docs)
- [Suricata Documentation](https://docs.suricata.io/)
- [osquery Documentation](https://osquery.readthedocs.io/)
- [VirusTotal API v3](https://developers.virustotal.com/reference)
