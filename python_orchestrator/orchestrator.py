import sys
import json
import requests
from rules import RULES

NODE_SERVER_URL = "http://localhost:4000/alert"

def send_alert_to_ui(alert_payload):
    """Sends a structured JSON alert to the Node.js UI server."""
    try:
        requests.post(NODE_SERVER_URL, json=alert_payload, timeout=1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not send alert to UI: {e}", file=sys.stderr, flush=True)

def process_event(event):
    """The main rule engine. Iterates through rules and applies them to an event."""

    for rule in RULES:
        if rule["logsource"] != event.get("event_type"):
            continue

        alert = None
        detection_logic = rule["detection"]

        if "keywords" in detection_logic and "field" in detection_logic:
            field_to_check = event.get(detection_logic["field"], "")
            if any(keyword in field_to_check for keyword in detection_logic["keywords"]):
                alert = format_alert(rule, event)

        elif "process_names" in detection_logic and "command_substring" in detection_logic:
            process_name = event.get("name", "")
            command_line = event.get("cmd", "")
            if process_name in detection_logic["process_names"] and detection_logic["command_substring"] in command_line:
                alert = format_alert(rule, event)

        if alert:
            send_alert_to_ui(alert)
            print(f"!!! ALERT Triggered: {alert.get('rule')} (Severity: {alert.get('severity')})", flush=True)
            break

def format_alert(rule, event):
    """Creates a rich alert object based on the rule and the event that triggered it."""
    alert = {
        "rule": rule["rule"],
        "description": rule["description"],
        "severity": rule["severity"],
        "type": rule["type"],
        "src": rule["logsource"].replace("_event", "").replace("_conn", ""),
        "tags": rule.get("tags", [])
    }
    source_key = alert["src"]
    if source_key:
        alert[source_key] = event

    return alert

def main():
    print("INFO: Python Rule Engine started. Waiting for telemetry...", file=sys.stderr, flush=True)
    for line in sys.stdin:
        try:
            event = json.loads(line)
            process_event(event)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    main()
