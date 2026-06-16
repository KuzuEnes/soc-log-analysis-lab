import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import unquote

LOG_FILE = Path("01-soc-basics/data/access.log")

access_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+)'
)

suspicious_paths = [
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

events = []

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        match = access_pattern.search(line)

        if not match:
            continue

        raw_path = match.group("path")
        decoded_path = unquote(raw_path).lower()

        event = {
            "ip": match.group("ip"),
            "timestamp": match.group("timestamp"),
            "method": match.group("method"),
            "path": raw_path,
            "decoded_path": decoded_path,
            "status": int(match.group("status")),
            "size": int(match.group("size")),
            "raw": line.strip()
        }

        events.append(event)

requests_by_ip = Counter(event["ip"] for event in events)
not_found_by_ip = Counter(event["ip"] for event in events if event["status"] == 404)

suspicious_path_hits = defaultdict(list)
sqli_hits = []
xss_hits = []

for event in events:
    decoded_path = event["decoded_path"]

    for suspicious_path in suspicious_paths:
        if suspicious_path in decoded_path:
            suspicious_path_hits[event["ip"]].append(event["path"])

    if any(pattern in decoded_path for pattern in sqli_patterns):
        sqli_hits.append(event)

    if any(pattern in decoded_path for pattern in xss_patterns):
        xss_hits.append(event)

print("\n=== WEB ACCESS LOG ANALYSIS ===")

print(f"\nTotal requests: {len(events)}")

print("\nRequests by IP:")
for ip, count in requests_by_ip.items():
    print(f"- {ip}: {count}")

print("\n[1] Possible Web Path Scan / Directory Scan:")
for ip, count in not_found_by_ip.items():
    if count >= 5:
        print(f"[ALERT] {ip} generated {count} HTTP 404 responses.")

print("\n[2] Suspicious Path Attempts:")
for ip, paths in suspicious_path_hits.items():
    print(f"[ALERT] {ip} requested suspicious paths:")
    for path in paths:
        print(f"  - {path}")

print("\n[3] Possible SQL Injection Attempts:")
for event in sqli_hits:
    print(f"[ALERT] SQLi marker detected from {event['ip']} -> {event['path']}")

print("\n[4] Possible XSS Attempts:")
for event in xss_hits:
    print(f"[ALERT] XSS marker detected from {event['ip']} -> {event['path']}")

print("\nConclusion:")

if not_found_by_ip or suspicious_path_hits or sqli_hits or xss_hits:
    print("Suspicious web activity detected. Review source IPs and requested paths.")
else:
    print("No obvious suspicious web activity detected.")
