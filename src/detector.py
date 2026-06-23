from models import Alert
from datetime import datetime, timedelta


def detect_bruteforce(entries):
    MAX_MINUTES = 5
    MID_SEVERITY = 5
    HIGH_SEVERITY = 10
    CRITICAL_SEVERITY = 20
    severity = None
    failed_logins = {}
    ip = None
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

        window = times[4] - times[0]

        # Checks if the window is greater than 5 minutes
        if window <= timedelta(minutes=MAX_MINUTES):
            for entry in entries:
                # Gets the ip address of the user
                if entry.user == user:
                    ip = entry.ip
                    break

            # Creates a new alert object
            alerts.append(Alert("Bruteforce attack", severity, user, ip))

    return alerts
