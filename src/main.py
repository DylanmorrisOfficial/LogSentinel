from parser import parse_log
from pathlib import Path

LOG_FILE = Path(__file__).parent.parent / "logs" / "sample.log"


def main():
    log_entries = parse_log(LOG_FILE)

    # Displays each entry in the file
    for entry in log_entries:
        print(entry)


# Main entry point for the Application
if __name__ == "__main__":
    main()
