import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

LOG_FILE = Path("01-soc-basics/data/auth.log")

failed_pattern = re.compile(
    r"(?P<month>\w+) (?P<day>\d+) (?P<time>\d+:\d+:\d+) .* Failed password for (?P<user>\w+) from (?P<ip>[\d\.]+)"
)

accepted_pattern = re.compile(
    r"(?P<month>\w+) (?P<day>\d+) (?P<time>\d+:\d+:\d+) .* Accepted password for (?P<user>\w+) from (?P<ip>[\d\.]+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_timestamp(month, day, time_value):
    hour, minute, second = map(int, time_value.split(":"))
    return datetime(
        year=2026,
        month=MONTHS[month],
        day=int(day),
        hour=hour,
        minute=minute,
        second=second
    )

events = []

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        failed_match = failed_pattern.search(line)
        accepted_match = accepted_pattern.search(line)

        if failed_match:
            events.append({
                "timestamp": parse_timestamp(
                    failed_match.group("month"),
                    failed_match.group("day"),
                    failed_match.group("time")
                ),
                "event_type": "failed",
                "user": failed_match.group("user"),
                "ip": failed_match.group("ip"),
                "raw": line.strip()
            })

        if accepted_match:
            events.append({
                "timestamp": parse_timestamp(
                    accepted_match.group("month"),
                    accepted_match.group("day"),
                    accepted_match.group("time")
                ),
                "event_type": "accepted",
                "user": accepted_match.group("user"),
                "ip": accepted_match.group("ip"),
                "raw": line.strip()
            })

events.sort(key=lambda event: event["timestamp"])

failed_events = [event for event in events if event["event_type"] == "failed"]
accepted_events = [event for event in events if event["event_type"] == "accepted"]

failed_by_ip = Counter(event["ip"] for event in failed_events)
failed_by_user = Counter(event["user"] for event in failed_events)

users_by_ip = defaultdict(set)

for event in failed_events:
    users_by_ip[event["ip"]].add(event["user"])

print("\n=== AUTH LOG ANALYSIS V2 ===")

print(f"\nTotal failed logins: {len(failed_events)}")
print(f"Total successful logins: {len(accepted_events)}")

print("\nFailed login count by IP:")
for ip, count in failed_by_ip.items():
    print(f"- {ip}: {count}")

print("\nFailed login count by user:")
for user, count in failed_by_user.items():
    print(f"- {user}: {count}")

print("\n[1] Possible brute force:")
for ip, count in failed_by_ip.items():
    if count >= 5:
        print(f"[ALERT] {ip} generated {count} failed login attempts.")

print("\n[2] Possible password spraying:")
for ip, users in users_by_ip.items():
    if len(users) >= 4:
        print(f"[ALERT] {ip} tried multiple users: {', '.join(sorted(users))}")

print("\n[3] Failed login followed by successful login:")

for accepted in accepted_events:
    same_ip_previous_failures = [
        event for event in failed_events
        if event["ip"] == accepted["ip"]
        and event["timestamp"] < accepted["timestamp"]
    ]

    same_user_previous_failures = [
        event for event in failed_events
        if event["user"] == accepted["user"]
        and event["timestamp"] < accepted["timestamp"]
    ]

    if len(same_ip_previous_failures) >= 3:
        print(
            f"[HIGH ALERT] Successful login after failed attempts. "
            f"IP={accepted['ip']} USER={accepted['user']} "
            f"FAILED_BEFORE={len(same_ip_previous_failures)}"
        )

    elif len(same_user_previous_failures) >= 3:
        print(
            f"[MEDIUM ALERT] User had previous failed attempts before success. "
            f"USER={accepted['user']} IP={accepted['ip']} "
            f"FAILED_BEFORE={len(same_user_previous_failures)}"
        )

print("\nConclusion:")
print("Review high alerts first. A successful login after multiple failures may indicate credential compromise.")
