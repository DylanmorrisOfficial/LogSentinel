from models import Alert
from datetime import datetime, timedelta


def detect_brute_force(entries):
    MAX_MINUTES = 5
    MID_SEVERITY = 5
    HIGH_SEVERITY = 10
    CRITICAL_SEVERITY = 20
    severity = None
    failed_logins = {}
    alerts = []

    # Loops through each entry
    for entry in entries:
        # Checks if the user has failed to login
        if entry.event == "LOGIN_FAILED":
            # Adds the user to failed_logins
            if entry.user not in failed_logins:
                failed_logins[entry.user] = []

            # Appends the timestamp of the log to the user list
            failed_logins[entry.user].append(datetime.fromisoformat(entry.timestamp))

    # Loops through items in failed_logins
    for user, times in failed_logins.items():
        attack_detected = False

        fail_count = len(times)

        # Sets the severity level for the alert
        if fail_count >= CRITICAL_SEVERITY:
            severity = "Critical"
        elif fail_count >= HIGH_SEVERITY:
            severity = "High"
        elif fail_count >= MID_SEVERITY:
            severity = "Medium"
        else:
            continue

        times.sort()

        # Checks if 5 consecutive failed logins occurred within a 5-minute window
        for i in range(len(times) - 4):
            window = times[i + 4] - times[i]

            # Checks if the window is greater than 5 minutes
            if window <= timedelta(minutes=MAX_MINUTES):
                attack_detected = True
                break

        if attack_detected:
            ip = None

            for entry in entries:
                # Gets the ip address of the user
                if entry.user == user:
                    ip = entry.ip
                    break
            # Creates a new alert object
            alerts.append(Alert("Bruteforce attack", severity, user, ip))

    return alerts


def detect_password_spray(entries):
    MAX_MINUTES = 5
    MID_SEVERITY = 5
    HIGH_SEVERITY = 10
    CRITICAL_SEVERITY = 20
    severity = None
    failed_logins = {}
    alerts = []

    # Loops through each entry
    for entry in entries:
        # Checks if the user has failed to login
        if entry.event == "LOGIN_FAILED":
            # Adds the ip address to failed_logins
            if entry.ip not in failed_logins:
                failed_logins[entry.ip] = {"users": set(), "times": []}

            # Stores the user and timestamp of the log entry
            failed_logins[entry.ip]["users"].add(entry.user)
            failed_logins[entry.ip]["times"].append(
                datetime.fromisoformat(entry.timestamp)
            )

    # Loops through items in failed_logins
    for ip, data in failed_logins.items():
        attack_detected = False

        users = data["users"]
        times = data["times"]

        user_count = len(users)

        # Sets the severity level for the alert
        if user_count >= CRITICAL_SEVERITY:
            severity = "Critical"
        elif user_count >= HIGH_SEVERITY:
            severity = "High"
        elif user_count >= MID_SEVERITY:
            severity = "Medium"
        else:
            continue

        times.sort()

        # Checks if 5 consecutive failed logins occurred within a 5-minute window
        for i in range(len(times) - 4):
            window = times[i + 4] - times[i]

            # Checks if the window is greater than 5 minutes
            if window <= timedelta(minutes=MAX_MINUTES):
                attack_detected = True
                break

        if attack_detected:
            # Creates a new alert object
            alerts.append(
                Alert("Password spraying", severity, f"{user_count} users targeted", ip)
            )

    return alerts
