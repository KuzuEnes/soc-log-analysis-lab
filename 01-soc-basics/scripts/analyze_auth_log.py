import re
from collections import Counter, defaultdict
from pathlib import Path

LOG_FILE = Path("01-soc-basics/data/auth.log")

failed_pattern = re.compile(
    r"Failed password for (?P<user>\w+) from (?P<ip>[\d\.]+)"
)

accepted_pattern = re.compile(
    r"Accepted password for (?P<user>\w+) from (?P<ip>[\d\.]+)"
)

failed_logins = []
accepted_logins = []

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        failed_match = failed_pattern.search(line)
        accepted_match = accepted_pattern.search(line)

        if failed_match:
            failed_logins.append({
                "user": failed_match.group("user"),
                "ip": failed_match.group("ip"),
                "raw": line.strip()
            })

        if accepted_match:
            accepted_logins.append({
                "user": accepted_match.group("user"),
                "ip": accepted_match.group("ip"),
                "raw": line.strip()
            })

failed_by_ip = Counter(item["ip"] for item in failed_logins)
failed_by_user = Counter(item["user"] for item in failed_logins)

print("\n=== AUTH LOG ANALYSIS ===")

print(f"\nTotal failed logins: {len(failed_logins)}")
print(f"Total successful logins: {len(accepted_logins)}")

print("\nFailed login count by IP:")
for ip, count in failed_by_ip.items():
    print(f"- {ip}: {count}")

print("\nFailed login count by user:")
for user, count in failed_by_user.items():
    print(f"- {user}: {count}")

print("\nSuspicious IPs:")
for ip, count in failed_by_ip.items():
    if count >= 5:
        print(f"[ALERT] Possible brute force from {ip} - {count} failed attempts")

print("\nConclusion:")
if any(count >= 5 for count in failed_by_ip.values()):
    print("There may be a brute force attempt.")
else:
    print("No obvious brute force pattern detected.")
