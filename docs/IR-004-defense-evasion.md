# Incident Report — IR-004
**Date:** 2026-04-01  
**Analyst:** Krystian  
**Severity:** CRITICAL  
**Status:** Resolved (Simulated)

## Summary
Two simultaneous alerts fired: `suspicious_process` (CRITICAL) and
`defense_evasion` (HIGH). Attacker used base64 encoding to obfuscate
a payload and applied chmod 777 to the decoded file — classic defense
evasion pattern to bypass file integrity checks.

## Timeline
| Time     | Event |
|----------|-------|
| 16:35:00 | Attacker encodes payload: base64 --decode |
| 16:35:10 | Attacker applies: chmod 777 /tmp/decoded.txt |
| 16:36:09 | Detection engine: suspicious_process ALERT — CRITICAL |
| 16:36:10 | Detection engine: defense_evasion ALERT — HIGH |
| 16:36:09 | Slack: 2 alerts fired simultaneously |
| 16:36:15 | osquery: modified_files ALERT — 2 items in /tmp/ |

## Detection
- **Rule:** `suspicious_process` — "base64 --decode" matched within
  10-minute window, threshold 1 — immediate CRITICAL alert
- **Rule:** `defense_evasion` — "base64 --decode" + "chmod 777"
  2 events in 5min, above threshold of 1
- **osquery:** modified_files detected /tmp/ writes

## MITRE ATT&CK
| Tactic | Technique | ID |
|--------|-----------|-----|
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | File and Directory Permissions Modification | T1222 |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 |

## Key Finding
Both rules fired within 1 second of each other — demonstrates correlation
capability of the detection engine. Single attacker action triggered
multiple detection layers simultaneously.

## Recommendations
1. Block base64 decode operations on files in /tmp/
2. Alert on chmod 777 applied to any executable file
3. Implement content inspection on decoded base64 payloads