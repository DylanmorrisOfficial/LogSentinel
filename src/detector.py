from models import Alert
from datetime import datetime, timedelta


def detect_bruteforce(entries):
    MAX_MINUTES = 5
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
        # Checks if there are more than 5 timestampes logged
        if len(times) >= 5:
            window = times[4] - times[0]

            # Checks if the window is within a 5 minute range
            if window <= timedelta(minutes=MAX_MINUTES):
                # Loops back through entries
                for entry in entries:
                    # Gets the ip address of the user with too many failed logins
                    if entry.user == user:
                        ip = entry.ip
                        break

                # Creates a new alert object
                alerts.append(Alert("Bruteforce attack", "Low", user, ip))

    return alerts
