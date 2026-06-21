from dataclasses import dataclass


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
            # Splits each part of the line
            parts = line.strip().split()

            # Stores the parts in a new logEntry
            entry = LogEntry(
                timestamp=parts[0], event=parts[1], user=parts[2], ip=parts[3]
            )

            entries.append(entry)

    return entries
