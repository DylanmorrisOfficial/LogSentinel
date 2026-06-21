from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address


@dataclass
class LogEntry:
    timestamp: str
    event: str
    user: str
    ip: str


def parse_log(filepath):
    entries = []

    with open(filepath) as file:
        # Reads each line of a file
        for line in file:
            line = line.strip()

            if not line:
                continue

            # Splits each part of the line
            parts = line.split()

            if len(parts) != 4:
                continue

            try:
                # Checks that the datetime and ip address are in the correct format
                datetime.fromisoformat(parts[0])
                ip_address(parts[3])
            except ValueError:
                continue

            # Adds each entry to entries
            entries.append(LogEntry(*parts))

    return entries
