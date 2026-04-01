# Incident Report — IR-001
**Date:** 2026-04-01  
**Analyst:** Krysti4n16  
**Severity:** HIGH  
**Status:** Resolved (Simulated)

## Summary
Detection engine triggered `privilege_escalation` rule during system 
reconnaissance phase. Attacker ran `ps aux`, `netstat -an`, `uname -a`, 
`ifconfig` and `whoami` to map the environment after gaining initial access.
osquery detected 2 files modified in suspicious locations (/tmp/).

## Timeline
| Time     | Event |
|----------|-------|
| 16:00:00 | Baseline established — 0 alerts |
| 16:02:00 | Attacker runs discovery commands: ps aux, netstat, uname, ifconfig |
| 16:02:23 | osquery: modified_files ALERT — 2 items in /tmp/ |
| 16:03:40 | Detection engine: privilege_escalation ALERT — 3 events / 5min |
| 16:03:40 | Slack alert fired — HIGH severity |

## Detection
- **Rule:** `privilege_escalation` — "operation not permitted" errors
  triggered by restricted path access during reconnaissance
- **osquery:** `modified_files` check detected output files written to /tmp/
- **Threshold:** 3 events / 5 minutes

## MITRE ATT&CK
| Tactic | Technique | ID |
|--------|-----------|-----|
| Discovery | Process Discovery | T1057 |
| Discovery | System Network Connections Discovery | T1049 |
| Discovery | System Information Discovery | T1082 |

## False Positive Analysis
Commands like `ps aux` and `netstat` are used legitimately by developers.
Key differentiator: volume of discovery commands in short time window
combined with /tmp/ file writes — typical attacker pattern.

## Recommendations
1. Alert on sequential execution of multiple discovery commands within 2min
2. Monitor /tmp/ writes by non-system processes
3. Implement application whitelisting for sensitive system commands