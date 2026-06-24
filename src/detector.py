from models import Alert
from datetime import datetime, timedelta


def get_severity(count):
    # Helper method to get the severity rate
    if count >= 20:
        return "Critical"

    if count >= 10:
        return "High"

    if count >= 5:
        return "Medium"

    return None


def detect_time_window(times, max_minutes=5):
    times.sort()

    # Checks if 5 consecutive failed logins occurred within a 5-minute window
    for i in range(len(times) - 4):
        window = times[i + 4] - times[i]

        # Checks if the window is greater than 5 minutes
        if window <= timedelta(minutes=max_minutes):
            return True

    return False


def detect_brute_force(entries):
    failed_logins = {}
    alerts = []

    # Stores the user, timestamp, and ip of each failed login attempt
    for entry in entries:
        if entry.event == "LOGIN_FAILED":
            if entry.user not in failed_logins:
                failed_logins[entry.user] = {
                    "times": [],
                    "ip": entry.ip,
                }

            failed_logins[entry.user]["times"].append(
                datetime.fromisoformat(entry.timestamp)
            )

    for user, data in failed_logins.items():
        times = data["times"]
        ip = data["ip"]

        fail_count = len(times)

        # Gets the severity based off of the number of failed login attempts
        severity = get_severity(fail_count)

        if severity is None:
            continue

        # Creates a new alert object if there were too many failed logins within a 5 minute time window
        if detect_time_window(times):
            alerts.append(
                Alert(
                    "Bruteforce attack",
                    severity,
                    user,
                    ip,
                )
            )

    return alerts


def detect_password_spray(entries):

    failed_logins = {}
    alerts = []

    # Stores the user, timestamp, and ip of each failed login attempt
    for entry in entries:
        if entry.event == "LOGIN_FAILED":
            if entry.ip not in failed_logins:
                failed_logins[entry.ip] = {
                    "users": set(),
                    "times": [],
                }

            failed_logins[entry.ip]["users"].add(entry.user)

            failed_logins[entry.ip]["times"].append(
                datetime.fromisoformat(entry.timestamp)
            )

    for ip, data in failed_logins.items():
        users = data["users"]
        times = data["times"]

        user_count = len(users)

        # Gets the severity based off of the number of failed login attempts
        severity = get_severity(user_count)

        if severity is None:
            continue

        # Creates a new alert object if there were too many failed logins within a 5 minute time window
        if detect_time_window(times):
            alerts.append(
                Alert(
                    "Password spraying",
                    severity,
                    f"{user_count} users targeted",
                    ip,
                )
            )

    return alerts
