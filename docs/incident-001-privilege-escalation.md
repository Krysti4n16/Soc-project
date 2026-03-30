# Incident Report — IR-001
**Date:** 2026-03-30  
**Severity:** HIGH  
**Status:** Resolved (Simulated)

## Summary
Detection engine triggered `privilege_escalation` rule after manual testing
of system access controls. Rule detected 6–7 events matching
"operation not permitted" within a 5-minute window.

## Timeline
| Time     | Event |
|----------|-------|
| 14:25:28 | Baseline established — 0 alerts |
| 14:31:xx | Analyst ran: `sudo cat /etc/sudoers`, `ls /var/root` |
| 14:33:29 | **ALERT fired** — privilege_escalation, 6 events / 5min |
| 14:34:29 | Alert persisted — 7 events, rule still triggered |
| 14:35:29 | Events dropped below threshold — alert cleared |

## Detection Logic
- **Rule:** `privilege_escalation`
- **Query:** `match_phrase` on "operation not permitted" 
- **Threshold:** 3 events / 5 minutes
- **Whitelisted processes:** biomesyncd, tccd, launchd, Safari

## Root Cause
Simulated privilege escalation attempt — analyst accessed restricted 
system paths (`/var/root`, `/private/var/db/sudo`) triggering macOS 
sandbox "operation not permitted" errors.

## MITRE ATT&CK Mapping
- **Tactic:** Privilege Escalation (TA0004)
- **Technique:** Abuse Elevation Control Mechanism (T1548)

## False Positive Analysis
Previous version of rule triggered 464 events/cycle due to partial 
keyword matching ("failed" matching "IORegisterForSystemPower failed").
Fixed by switching to `match_phrase` and process whitelisting.
Tuned from 0 false positives on clean baseline.

## Recommendations
1. Monitor `sudo` usage patterns across user sessions
2. Alert on repeated `ls /var/root` or similar privileged path access
3. Correlate with authentication logs for complete picture