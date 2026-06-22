from models import Alert


def detect_bruteforce(entries):
    MAX_LOGIN_ATTEMPTS = 5
    failed_logins = {}
    ip = None
    alerts = []

    # Loops through each entry
    for entry in entries:
        # Checks if the user has failed to login
        if entry.event == "LOGIN_FAILED":
            if entry.user not in failed_logins:
                # Stores the users name and increases their failed logins by 1
                failed_logins[entry.user] = 1
            else:
                # Increases the users failed logins by 1
                failed_logins[entry.user] += 1

    # Loops through item in failed_logins
    for user, count in failed_logins.items():
        # Checks if the users failed login count is greater than or equal to 5
        if count >= MAX_LOGIN_ATTEMPTS:
            # Loops back through entries
            for entry in entries:
                # Gets the ip address of the user with too many failed logins
                if entry.user == user:
                    ip = entry.ip
                    break

            # Creates a new alert object
            alerts.append(Alert("Bruteforce attack", "Low", user, ip))

    return alerts
