# Incident Report — IR-002
**Date:** 2026-03-30   
**Severity:** MEDIUM  
**Status:** Resolved (Simulated)

## Summary
Detection engine triggered `network_scan` rule after simulated brute-force
SSH connection attempts to localhost. 51 connection refused events detected
within 2-minute window — consistent with automated scanning behaviour.

## Timeline
| Time     | Event |
|----------|-------|
| 14:25:28 | Baseline — 0 network alerts |
| 14:34:xx | Analyst ran: `for i in {1..10}; do ssh wronguser@localhost; done` |
| 14:35:29 | **ALERT fired** — network_scan, 51 events / 2min |
| 14:36:30 | Alert cleared after activity stopped |

## Detection Logic
- **Rule:** `network_scan`  
- **Query:** `match_phrase` on "connection refused", "connection reset by peer"
- **Threshold:** 15 events / 2 minutes
- **Excluded processes:** Safari, WebKit, nsurlsessiond

## Root Cause
Simulated SSH scanning — rapid sequential connection attempts to localhost
port 22 generated 51 "Socket SO_ERROR [61: Connection refused]" events.
Spike from 0 to 51 events in single cycle is strong anomaly indicator.

## MITRE ATT&CK Mapping
- **Tactic:** Discovery (TA0007)
- **Technique:** Network Service Discovery (T1046)

## Recommendations
1. Block repeated SSH failures at firewall level after 5 attempts
2. Implement rate limiting on SSH connections
3. Alert on any external IP generating >10 connection refused / minute