import subprocess
import json
import requests
from datetime import datetime, timezone, timedelta
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from slack_notifier import send_alert as slack_alert

ES_URL= "http://localhost:9200"
OSQUERY_INDEX= "soc-osquery"

SUSPICIOUS_PORTS= {4444, 1337, 31337, 8080, 8888, 9001, 6666}
SUSPICIOUS_PROCESSES= {"nmap", "nc", "netcat", "tcpdump", "wireshark", "metasploit"}

def create_osquery_index():
    mapping= {
        "mappings": {
            "properties": {
                "timestamp":   {"type": "date"},
                "check":       {"type": "keyword"},
                "severity":    {"type": "keyword"},
                "description": {"type": "text"},
                "data":        {"type": "object"},
            }
        }
    }
    r= requests.put(f"{ES_URL}/{OSQUERY_INDEX}", json=mapping)
    if r.status_code in (200, 400):
        print(f"osquery index '{OSQUERY_INDEX}' ready")

def run_query(sql):
    try:
        result= subprocess.run(
            ["osqueryi", "--json", sql],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"osquery error: {e}")
        return []

def save_to_es(check_name, severity, description, data):
    doc= {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "check":       check_name,
        "severity":    severity,
        "description": description,
        "data":        data,
    }
    requests.post(f"{ES_URL}/{OSQUERY_INDEX}/_doc", json=doc)

def check_listening_ports():
    rows= run_query("""
        SELECT pid, name, port, address, protocol
        FROM listening_ports JOIN processes USING (pid)
        WHERE port != 0
        ORDER BY port
    """)

    found= []
    for row in rows:
        try:
            port= int(row.get("port", 0))
        except ValueError:
            continue
        if port in SUSPICIOUS_PORTS:
            found.append(row)

    if found:
        desc= f"Suspicious open port: {[r['port'] for r in found]}"
        save_to_es("suspicious_port", "HIGH", desc, found)
        slack_alert("suspicious_port", "HIGH", desc, len(found), 0,
                   [f"[{r['name']}] port {r['port']}" for r in found])
        return True, found
    return False, []

def check_active_connections():
    rows= run_query("""
        SELECT p.pid, p.name, s.remote_address, s.remote_port, s.state
        FROM process_open_sockets s JOIN processes p USING (pid)
        WHERE s.state = 'ESTABLISHED'
          AND s.remote_address NOT LIKE '127.%'
          AND s.remote_address NOT LIKE '10.%'
          AND s.remote_address NOT LIKE '192.168.%'
          AND s.remote_address != ''
          AND s.remote_address != '0.0.0.0'
        ORDER BY p.name
    """)

    suspicious= [r for r in rows if r.get("name", "").lower() in SUSPICIOUS_PROCESSES]

    if suspicious:
        desc= f"Suspicious process with external connection: {[r['name'] for r in suspicious]}"
        save_to_es("suspicious_connection", "CRITICAL", desc, suspicious)
        slack_alert("suspicious_connection", "CRITICAL", desc, len(suspicious), 0,
                   [f"[{r['name']}] → {r['remote_address']}:{r['remote_port']}" for r in suspicious])
        return True, suspicious

    return False, rows

def check_recently_modified_files():
    since= int((datetime.now() - timedelta(minutes=10)).timestamp())
    rows= run_query(f"""
        SELECT path, mtime, size
        FROM file
        WHERE (
            path LIKE '/tmp/%' OR
            path LIKE '/var/tmp/%' OR
            path LIKE '/Users/%/Library/LaunchAgents/%'
        )
        AND mtime > {since}
        AND size > 0
    """)

    if rows:
        desc= f"Files modified in suspicious locations: {len(rows)} files"
        save_to_es("suspicious_files", "MEDIUM", desc, rows[:10])
        if len(rows) > 3:
            slack_alert("suspicious_files", "MEDIUM", desc, len(rows), 10,
                       [r["path"] for r in rows[:3]])
        return True, rows

    return False, []

def check_new_launch_agents():
    rows= run_query("""
        SELECT name, path, program, program_arguments
        FROM launchd
        WHERE path LIKE '/Users/%/Library/LaunchAgents/%'
           OR path LIKE '/Library/LaunchAgents/%'
    """)

    if rows:
        desc= f"LaunchAgents found: {len(rows)}"
        save_to_es("launch_agents", "LOW", desc, rows)
        return True, rows

    return False, []

def run_osquery_checks():
    print(f"\nosquery scan — {datetime.now().strftime('%H:%M:%S')}")
    print(f"  {'Check':<30} {'Status'}")
    print(f"  {'-'*30} {'-'*30}")

    checks= [
        ("listening_ports",    check_listening_ports),
        ("active_connections", check_active_connections),
        ("modified_files",     check_recently_modified_files),
        ("launch_agents",      check_new_launch_agents),
    ]

    for name, fn in checks:
        triggered, data= fn()
        if triggered:
            print(f"  {name:<30} ALERT ({len(data)} items)")
        else:
            count= len(data) if data else 0
            print(f"  {name:<30} OK ({count} items)")

def run():
    print("SOC Lab — osquery Monitor")
    create_osquery_index()
    print("Running every 120s | Ctrl+C to stop\n")

    while True:
        run_osquery_checks()
        next_run= (datetime.now() + timedelta(seconds=120)).strftime('%H:%M:%S')
        print(f"\n  Next scan: {next_run}")
        time.sleep(120)

if __name__ == "__main__":
    run()