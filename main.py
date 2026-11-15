
import os
import json
from collections import Counter
from datetime import datetime

BASE_FOLDER = os.path.dirname(os.path.abspath(__file__))


def load_file(filename):
    """Read a file and return its lines."""
    filepath = os.path.join(BASE_FOLDER, filename)

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        print("Error: " + filename + " was not found.")
        return []
    except OSError as error:
        print("Could not read " + filename + ":", error)
        return []


def load_suspicious_ips():
    """Load suspicious IP addresses from the supplied file."""
    lines = load_file("suspicious_ips.txt")
    return set(line.strip() for line in lines if line.strip())


def get_fields(parts):
    """Convert log fields into a dictionary."""
    fields = {}

    for item in parts:
        if "=" in item:
            key, value = item.split("=", 1)
            fields[key] = value

    return fields


def parse_firewall(lines):
    """Parse firewall log entries."""
    events = []
    malformed = 0

    for line in lines:
        parts = line.strip().split()

        try:
            if len(parts) < 8:
                raise ValueError("Incomplete entry")

            timestamp = parts[0] + " " + parts[1]
            datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            action = parts[2]
            fields = get_fields(parts[3:])

            required = ["src", "dst", "proto", "port", "bytes"]

            if action not in ["ALLOWED", "BLOCKED"]:
                raise ValueError("Unknown action")

            if not all(key in fields for key in required):
                raise ValueError("Missing fields")

            port = int(fields["port"])
            byte_count = int(fields["bytes"])

            if not 1 <= port <= 65535 or byte_count < 0:
                raise ValueError("Invalid values")

            events.append({
                "action": action,
                "src": fields["src"],
                "dst": fields["dst"],
                "proto": fields["proto"],
                "port": port,
                "bytes": byte_count
            })

        except (ValueError, IndexError):
            malformed += 1

    return events, malformed


def parse_authentication(lines):
    """Parse authentication log entries."""
    events = []
    malformed = 0

    valid_events = [
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "ACCOUNT_LOCKED",
        "LOGOUT"
    ]

    for line in lines:
        parts = line.strip().split()

        try:
            if len(parts) < 7:
                raise ValueError("Incomplete entry")

            timestamp = parts[0] + " " + parts[1]
            datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            event = parts[2]
            fields = get_fields(parts[3:])

            required = ["user", "src", "host", "method"]

            if event not in valid_events:
                raise ValueError("Unknown event")

            if not all(key in fields for key in required):
                raise ValueError("Missing fields")

            events.append({
                "event": event,
                "user": fields["user"],
                "src": fields["src"],
                "host": fields["host"],
                "method": fields["method"]
            })

        except (ValueError, IndexError):
            malformed += 1

    return events, malformed


def analyse_data(firewall, authentication, suspicious_ips):
    """Analyse firewall and authentication events."""

    firewall_actions = Counter()
    blocked_ips = Counter()
    blocked_ports = Counter()
    unique_ips = set()

    for event in firewall:
        firewall_actions[event["action"]] += 1
        unique_ips.add(event["src"])

        if event["action"] == "BLOCKED":
            blocked_ips[event["src"]] += 1
            blocked_ports[event["port"]] += 1

    auth_events = Counter()
    failed_ips = Counter()
    failed_users = Counter()

    for event in authentication:
        auth_events[event["event"]] += 1

        if event["event"] == "LOGIN_FAILED":
            failed_ips[event["src"]] += 1
            failed_users[event["user"]] += 1

    # Compare suspicious IPs with both log files
    suspicious_results = {}

    for ip in sorted(suspicious_ips):
        blocked_count = sum(
            1 for event in firewall
            if event["src"] == ip and event["action"] == "BLOCKED"
        )

        failed_count = sum(
            1 for event in authentication
            if event["src"] == ip and event["event"] == "LOGIN_FAILED"
        )

        suspicious_results[ip] = {
            "blocked_events": blocked_count,
            "failed_logins": failed_count
        }

    return {
        "firewall": {
            "valid_events": len(firewall),
            "allowed": firewall_actions["ALLOWED"],
            "blocked": firewall_actions["BLOCKED"],
            "unique_source_ips": len(unique_ips),
            "top_blocked_ips": blocked_ips.most_common(5),
            "top_blocked_ports": blocked_ports.most_common(5)
        },
        "authentication": {
            "valid_events": len(authentication),
            "successful_logins": auth_events["LOGIN_SUCCESS"],
            "failed_logins": auth_events["LOGIN_FAILED"],
            "account_locked": auth_events["ACCOUNT_LOCKED"],
            "logouts": auth_events["LOGOUT"],
            "top_failed_ips": failed_ips.most_common(5),
            "top_failed_users": failed_users.most_common(5)
        },
        "suspicious_ip_correlation": suspicious_results
    }


def generate_report(results, firewall_bad, auth_bad):
    """Display and save the investigation report."""

    report = []
    report.append("SECURITY LOG INVESTIGATION REPORT")
    report.append("=" * 40)

    fw = results["firewall"]
    auth = results["authentication"]

    report.append("\nFIREWALL ANALYSIS")
    report.append("-" * 25)
    report.append("Valid events: " + str(fw["valid_events"]))
    report.append("Allowed events: " + str(fw["allowed"]))
    report.append("Blocked events: " + str(fw["blocked"]))
    report.append("Unique source IPs: " + str(fw["unique_source_ips"]))

    report.append("\nTop blocked source IPs:")
    for ip, count in fw["top_blocked_ips"]:
        report.append(ip + " - " + str(count) + " blocked events")

    report.append("\nMost targeted blocked ports:")
    for port, count in fw["top_blocked_ports"]:
        report.append("Port " + str(port) + " - " + str(count) + " events")

    report.append("\nAUTHENTICATION ANALYSIS")
    report.append("-" * 25)
    report.append("Valid events: " + str(auth["valid_events"]))
    report.append("Successful logins: " + str(auth["successful_logins"]))
    report.append("Failed logins: " + str(auth["failed_logins"]))
    report.append("Account locked events: " + str(auth["account_locked"]))
    report.append("Logouts: " + str(auth["logouts"]))

    report.append("\nTop failed-login source IPs:")
    for ip, count in auth["top_failed_ips"]:
        report.append(ip + " - " + str(count) + " failed logins")

    report.append("\nMost targeted usernames:")
    for user, count in auth["top_failed_users"]:
        report.append(user + " - " + str(count) + " failed logins")

    report.append("\nDATA QUALITY")
    report.append("-" * 25)
    report.append("Malformed firewall lines: " + str(firewall_bad))
    report.append("Malformed authentication lines: " + str(auth_bad))

    report.append("\nSECURITY OBSERVATIONS")
    report.append("-" * 25)

    if fw["blocked"] > fw["allowed"]:
        report.append("More firewall events were blocked than allowed.")
    else:
        report.append("Allowed firewall events were equal to or higher than blocked events.")

    if auth["failed_logins"] > auth["successful_logins"]:
        report.append("Failed logins exceeded successful logins.")
    else:
        report.append("Successful logins were equal to or higher than failed logins.")

    if auth["top_failed_ips"]:
        ip, count = auth["top_failed_ips"][0]
        report.append(
            "The most frequent failed-login source was "
            + ip + " with " + str(count) + " attempts."
        )

    # Suspicious IP correlation results
    report.append("\nSUSPICIOUS IP CORRELATION")
    report.append("-" * 25)

    for ip, details in results["suspicious_ip_correlation"].items():
        report.append(
            ip + " - Blocked events: "
            + str(details["blocked_events"])
            + ", Failed logins: "
            + str(details["failed_logins"])
        )

    report_text = "\n".join(report)

    print("\n" + report_text)

    txt_path = os.path.join(BASE_FOLDER, "investigation_report.txt")
    json_path = os.path.join(BASE_FOLDER, "investigation_report.json")

    try:
        with open(txt_path, "w", encoding="utf-8") as file:
            file.write(report_text)

        with open(json_path, "w", encoding="utf-8") as file:
            json.dump(results, file, indent=4)

        print("\nReports saved successfully.")

    except OSError as error:
        print("Could not save reports:", error)


def main():
    print("Starting Security Log Investigation...")

    firewall_lines = load_file("firewall.log")
    auth_lines = load_file("authentication.log")

    suspicious_ips = load_suspicious_ips()

    firewall, firewall_bad = parse_firewall(firewall_lines)
    authentication, auth_bad = parse_authentication(auth_lines)

    results = analyse_data(
        firewall,
        authentication,
        suspicious_ips
    )

    generate_report(results, firewall_bad, auth_bad)


if __name__ == "__main__":
    main()
