# Incident Report — IR-005
**Date:** 2026-04-01  
**Analyst:** Krystian  
**Severity:** CRITICAL  
**Status:** Resolved (Simulated)

## Summary
Attacker simulated data exfiltration via DNS queries and HTTP POST.
Detection engine triggered `suspicious_process` (CRITICAL) on base64
operations used to encode data before transmission. `defense_evasion`
rule also fired on obfuscation activity.

## Timeline
| Time     | Event |
|----------|-------|
| 16:42:00 | Attacker runs base64 --decode on sensitive file |
| 16:42:10 | Attacker sends HTTP POST to external endpoint (httpbin.org) |
| 16:42:19 | osquery: active_connections — 5 items (was 4) |
| 16:43:16 | Detection engine: suspicious_process ALERT — 2 events / 10min |
| 16:43:16 | Detection engine: defense_evasion ALERT — 1 event / 5min |
| 16:40:14 | Slack: defense_evasion alert — HIGH |

## Detection
- **Rule:** `suspicious_process` — base64 operations matched twice
  in 10-minute window
- **Rule:** `defense_evasion` — obfuscation activity detected
- **osquery:** active_connections increased from 4 to 5 — new external
  connection detected during exfiltration window

## MITRE ATT&CK
| Tactic | Technique | ID |
|--------|-----------|-----|
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Command and Control | Application Layer Protocol: DNS | T1071.004 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

## Network Indicators
- Outbound HTTP POST to httpbin.org:443
- DNS queries to multiple external domains in rapid succession
- New TCP connection during active alert window

## Recommendations
1. Implement DLP — block HTTP POST with encoded payloads
2. Monitor DNS query frequency — >10 queries/min to new domains = alert
3. Correlate network connections with simultaneous base64 activity
4. Deploy Suricata rule: alert on POST requests with base64 body content