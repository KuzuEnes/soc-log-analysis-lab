import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

AUTH_LOG = Path("01-soc-basics/data/auth.log")
ACCESS_LOG = Path("01-soc-basics/data/access.log")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

auth_failed_pattern = re.compile(
    r"(?P<month>\w+) (?P<day>\d+) (?P<time>\d+:\d+:\d+) .* "
    r"Failed password for (?P<user>\w+) from (?P<ip>[\d\.]+)"
)

auth_accepted_pattern = re.compile(
    r"(?P<month>\w+) (?P<day>\d+) (?P<time>\d+:\d+:\d+) .* "
    r"Accepted password for (?P<user>\w+) from (?P<ip>[\d\.]+)"
)

access_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

suspicious_web_paths = [
    "/admin",
    "/wp-login.php",
    "/.git",
    "/backup",
    "/phpinfo.php",
    "/config.php",
]

sqli_patterns = [
    " or 1=1",
    "' or 1=1",
    "union select",
    "information_schema",
    "--",
]

xss_patterns = [
    "<script>",
    "</script>",
    "onerror=",
    "javascript:",
    "<img",
]


def parse_auth_timestamp(month, day, time_value):
    hour, minute, second = map(int, time_value.split(":"))
    return datetime(
        year=2026,
        month=MONTHS[month],
        day=int(day),
        hour=hour,
        minute=minute,
        second=second
    )


def parse_access_timestamp(timestamp):
    # Example: 16/Jun/2026:22:11:01 +0300
    return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)


auth_events = []
web_events = []

with AUTH_LOG.open("r", encoding="utf-8") as file:
    for line in file:
        failed_match = auth_failed_pattern.search(line)
        accepted_match = auth_accepted_pattern.search(line)

        if failed_match:
            auth_events.append({
                "timestamp": parse_auth_timestamp(
                    failed_match.group("month"),
                    failed_match.group("day"),
                    failed_match.group("time")
                ),
                "ip": failed_match.group("ip"),
                "user": failed_match.group("user"),
                "event_type": "auth_failed",
                "raw": line.strip()
            })

        if accepted_match:
            auth_events.append({
                "timestamp": parse_auth_timestamp(
                    accepted_match.group("month"),
                    accepted_match.group("day"),
                    accepted_match.group("time")
                ),
                "ip": accepted_match.group("ip"),
                "user": accepted_match.group("user"),
                "event_type": "auth_success",
                "raw": line.strip()
            })

with ACCESS_LOG.open("r", encoding="utf-8") as file:
    for line in file:
        match = access_pattern.search(line)

        if not match:
            continue

        raw_path = match.group("path")
        decoded_path = unquote(raw_path).lower()
        status = int(match.group("status"))

        indicators = []

        if status == 404:
            indicators.append("http_404")

        if any(path in decoded_path for path in suspicious_web_paths):
            indicators.append("suspicious_path")

        if any(pattern in decoded_path for pattern in sqli_patterns):
            indicators.append("sqli_marker")

        if any(pattern in decoded_path for pattern in xss_patterns):
            indicators.append("xss_marker")

        web_events.append({
            "timestamp": parse_access_timestamp(match.group("timestamp")),
            "ip": match.group("ip"),
            "method": match.group("method"),
            "path": raw_path,
            "decoded_path": decoded_path,
            "status": status,
            "event_type": "web_request",
            "indicators": indicators,
            "raw": line.strip()
        })

auth_ips = set(event["ip"] for event in auth_events)
web_ips = set(event["ip"] for event in web_events)
common_ips = auth_ips.intersection(web_ips)

failed_by_ip = Counter(
    event["ip"] for event in auth_events
    if event["event_type"] == "auth_failed"
)

success_by_ip = Counter(
    event["ip"] for event in auth_events
    if event["event_type"] == "auth_success"
)

web_404_by_ip = Counter(
    event["ip"] for event in web_events
    if "http_404" in event["indicators"]
)

web_suspicious_by_ip = defaultdict(list)

for event in web_events:
    if event["indicators"]:
        web_suspicious_by_ip[event["ip"]].append(event)

print("\n=== AUTH + WEB CORRELATION ANALYSIS ===")

print(f"\nTotal auth events: {len(auth_events)}")
print(f"Total web events: {len(web_events)}")

print("\nIPs seen in both auth.log and access.log:")
if common_ips:
    for ip in sorted(common_ips):
        print(f"- {ip}")
else:
    print("- No common IPs found.")

print("\nCorrelation Findings:")

for ip in sorted(common_ips):
    risk_score = 0
    reasons = []

    failed_count = failed_by_ip.get(ip, 0)
    success_count = success_by_ip.get(ip, 0)
    web_404_count = web_404_by_ip.get(ip, 0)
    suspicious_web_count = len(web_suspicious_by_ip.get(ip, []))

    if failed_count >= 3:
        risk_score += 30
        reasons.append(f"{failed_count} failed SSH login attempts")

    if success_count >= 1 and failed_count >= 1:
        risk_score += 30
        reasons.append("successful SSH login after failed attempts")

    if web_404_count >= 5:
        risk_score += 20
        reasons.append(f"{web_404_count} HTTP 404 responses")

    if suspicious_web_count >= 3:
        risk_score += 20
        reasons.append(f"{suspicious_web_count} suspicious web requests")

    if risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    elif risk_score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    print(f"\nIP: {ip}")
    print(f"Severity: {severity}")
    print(f"Risk Score: {risk_score}")

    if reasons:
        print("Reasons:")
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("Reasons:")
        print("- No strong suspicious correlation found.")

    if ip in web_suspicious_by_ip:
        print("Suspicious web paths:")
        for event in web_suspicious_by_ip[ip]:
            print(f"- {event['path']} | indicators={','.join(event['indicators'])}")

print("\nConclusion:")
print("IPs appearing in multiple log sources should be reviewed first, especially if they show both authentication failures and suspicious web activity.")
