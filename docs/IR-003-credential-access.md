# Incident Report — IR-003
**Date:** 2026-04-01  
**Analyst:** Krystian  
**Severity:** HIGH  
**Status:** Resolved (Simulated)

## Summary
Attacker attempted to access macOS Keychain and search for credentials
in system preference files. Detection engine triggered `privilege_escalation`
rule on repeated "operation not permitted" errors from keychain access
attempts. 9 events detected in 5-minute window.

## Timeline
| Time     | Event |
|----------|-------|
| 16:12:00 | Attacker runs: security list-keychains |
| 16:12:10 | Attacker runs: security dump-keychain |
| 16:12:20 | Attacker runs: grep -r "password" ~/Library/Preferences/ |
| 16:13:48 | Detection engine: privilege_escalation ALERT — 9 events / 5min |
| 16:13:48 | Slack alert fired — HIGH severity |
| 16:14:33 | osquery: modified_files ALERT — 2 items |

## Detection
- **Rule:** `privilege_escalation` — keychain access denied errors
  generated "operation not permitted" and "listener failed to activate"
  messages caught by detection engine
- **Count:** 9 events in 5min — 3x above threshold of 3

## MITRE ATT&CK
| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Credentials from Password Stores | T1555 |
| Credential Access | Keychain | T1555.001 |
| Discovery | File and Directory Discovery | T1083 |

## Recommendations
1. Enable macOS Keychain access logging
2. Alert on `security dump-keychain` command execution
3. Restrict Keychain access to signed, whitelisted applications only