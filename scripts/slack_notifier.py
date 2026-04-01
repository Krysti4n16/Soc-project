import requests
import os
from datetime import datetime

def get_webhook_url():
    url= os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        try:
            with open(os.path.join(os.path.dirname(__file__), "../.env")) as f:
                for line in f:
                    if line.startswith("SLACK_WEBHOOK_URL="):
                        url = line.strip().split("=", 1)[1]
        except FileNotFoundError:
            pass
    return url

SEVERITY_EMOJI= {
    "CRITICAL": ":rotating_light:",
    "HIGH":     ":red_circle:",
    "MEDIUM":   ":large_yellow_circle:",
    "LOW":      ":large_green_circle:",
}

def send_alert(rule_name, severity, description, count, window_min, samples=None):
    url= get_webhook_url()
    if not url:
        print("No SLACK_WEBHOOK_URL in .env")
        return False

    emoji= SEVERITY_EMOJI.get(severity, ":white_circle:")
    ts= datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    blocks= [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} SOC Alert — {severity}"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Rule:*\n`{rule_name}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                {"type": "mrkdwn", "text": f"*Events:*\n{count} in {window_min} min"},
                {"type": "mrkdwn", "text": f"*Time:*\n{ts}"},
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Description:*\n{description}"
            }
        }
    ]

    if samples:
        sample_text= "\n".join(f"`{s[:80]}`" for s in samples[:2])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Sample events:*\n{sample_text}"
            }
        })

    blocks.append({"type": "divider"})

    payload = {"blocks": blocks}
    try:
        r = requests.post(url, json=payload, timeout=5)
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"Slack error: {e}")
        return False

def send_vt_threat(ip, verdict, country, as_owner, threat_names, vt_link):
    url= get_webhook_url()
    if not url:
        return False

    emoji= ":skull:" if verdict == "MALICIOUS" else ":warning:"
    threats_text= ", ".join(threat_names) if threat_names else "unknown"

    blocks= [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} VirusTotal — {verdict} IP detected"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*IP:*\n`{ip}`"},
                {"type": "mrkdwn", "text": f"*Verdict:*\n{verdict}"},
                {"type": "mrkdwn", "text": f"*Country:*\n{country}"},
                {"type": "mrkdwn", "text": f"*Owner:*\n{as_owner}"},
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Threat names:*\n{threats_text}\n\n<{vt_link}|View on VirusTotal>"
            }
        },
        {"type": "divider"}
    ]

    payload= {"blocks": blocks}
    try:
        r = requests.post(url, json=payload, timeout=5)
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"Slack VT error: {e}")
        return False

if __name__ == "__main__":
    print("Sending test alert to Slack")
    ok = send_alert(
        rule_name="network_scan",
        severity="MEDIUM",
        description="Serial connection refusals — possible port scan",
        count=75,
        window_min=2,
        samples=["[ssh] Socket SO_ERROR [61: Connection refused]"]
    )
    print("Sent" if ok else "Failed — check webhook URL in .env")