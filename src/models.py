from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: str
    event: str
    user: str
    ip: str


@dataclass
class Alert:
    alert_type: str
    severity: str
    user: str
    ip: str
