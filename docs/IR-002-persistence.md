# Incident Report — IR-002
**Date:** 2026-04-01  
**Analyst:** Krystian  
**Severity:** HIGH  
**Status:** Resolved (Simulated)

## Summary
Attacker established persistence by dropping a malicious LaunchAgent plist
into ~/Library/LaunchAgents/. This technique survives reboots and executes
automatically at user login. osquery detected the new agent within 2 minutes.
Slack alert fired automatically.

## Timeline
| Time     | Event |
|----------|-------|
| 16:05:00 | Attacker creates com.soc.test.plist in /tmp/ |
| 16:05:10 | Attacker copies plist to ~/Library/LaunchAgents/ |
| 16:06:26 | osquery: launch_agents ALERT — 5 items (was 4) |
| 16:06:42 | Detection engine: privilege_escalation ALERT — 6 events / 5min |
| 16:08:29 | Slack alert: suspicious_files MEDIUM — 4 files in /tmp/ |

## Detection
- **osquery:** `launch_agents` check monitors ~/Library/LaunchAgents/ 
  and /Library/LaunchAgents/ — new entry detected immediately
- **osquery:** `modified_files` detected plist written to /tmp/
- **Slack:** automatic notification within 2 minutes of file drop

## MITRE ATT&CK
| Tactic | Technique | ID |
|--------|-----------|-----|
| Persistence | Launch Agent | T1543.001 |
| Defense Evasion | Masquerading | T1036 |

## Indicators of Compromise
- File: `~/Library/LaunchAgents/com.soc.test.plist`
- Label: `com.soc.test`
- Program: `/bin/bash -c echo test`

## Recommendations
1. Baseline all existing LaunchAgents — alert on any new additions
2. Verify plist signatures — legitimate Apple agents are signed
3. Monitor LaunchAgents directories with real-time file integrity monitoring