from parser import parse_log
from pathlib import Path
from detector import detect_brute_force, detect_password_spray

LOG_FILE = Path(__file__).parent.parent / "logs" / "sample.log"


def main():
    log_entries = parse_log(LOG_FILE)

    alerts = detect_password_spray(log_entries)
    brute = detect_brute_force(log_entries)

    print(alerts)
    print(brute)


# Main entry point for the Application
if __name__ == "__main__":
    main()
