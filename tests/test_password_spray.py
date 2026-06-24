import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import detect_password_spray
from models import LogEntry


def test_medium_severity():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(
                f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", f"user{i}", "192.168.1.100"
            )
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "Medium"


def test_high_severity():
    entries = []

    for i in range(10):
        entries.append(
            LogEntry(
                f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", f"user{i}", "192.168.1.100"
            )
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "High"


def test_critical_severity():
    entries = []

    for i in range(20):
        entries.append(
            LogEntry(
                f"2026-06-17T10:{i:02}:00", "LOGIN_FAILED", f"user{i}", "192.168.1.100"
            )
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "Critical"


def test_below_threshold():
    entries = []

    for i in range(4):
        entries.append(
            LogEntry(
                f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", f"user{i}", "192.168.1.100"
            )
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 0


def test_outside_time_window():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(
                f"2026-06-17T10:0{i * 2}:00",
                "LOGIN_FAILED",
                f"user{i}",
                "192.168.1.100",
            )
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 0


def test_multiple_attacking_ips():

    entries = []

    for i in range(5):
        entries.append(
            LogEntry(
                f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", f"user{i}", "192.168.1.100"
            )
        )

    for i in range(5):
        entries.append(
            LogEntry(
                f"2026-06-17T11:0{i}:00", "LOGIN_FAILED", f"admin{i}", "192.168.1.200"
            )
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 2


def test_same_user_does_not_trigger_password_spray():

    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "alice", "192.168.1.100")
        )

    alerts = detect_password_spray(entries)

    assert len(alerts) == 0
