from parser import parse_log
from pathlib import Path
from detector import detect_bruteforce

LOG_FILE = Path(__file__).parent.parent / "logs" / "sample.log"


def main():
    log_entries = parse_log(LOG_FILE)

    alerts = detect_bruteforce(log_entries)

    print(alerts)


# Main entry point for the Application
if __name__ == "__main__":
    main()
