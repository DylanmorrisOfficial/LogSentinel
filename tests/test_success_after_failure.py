import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import detect_success_after_failure
from models import LogEntry


def test_success_after_failures_detected():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    entries.append(
        LogEntry("2026-06-17T10:05:00", "LOGIN_SUCCESS", "bob", "192.168.1.15")
    )

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "High"
    assert alerts[0].user == "bob"
    assert alerts[0].ip == "192.168.1.15"


def test_no_alert_without_success():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 0


def test_no_alert_below_failure_threshold():
    entries = []

    for i in range(4):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    entries.append(
        LogEntry("2026-06-17T10:04:30", "LOGIN_SUCCESS", "bob", "192.168.1.15")
    )

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 0


def test_no_alert_outside_time_window():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    entries.append(
        LogEntry("2026-06-17T10:20:00", "LOGIN_SUCCESS", "bob", "192.168.1.15")
    )

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 0


def test_no_alert_different_ip():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    entries.append(LogEntry("2026-06-17T10:05:00", "LOGIN_SUCCESS", "bob", "10.0.0.50"))

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 0


def test_no_alert_for_different_user_success():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    entries.append(
        LogEntry("2026-06-17T10:05:00", "LOGIN_SUCCESS", "alice", "192.168.1.15")
    )

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 0


def test_entries_out_of_order():
    entries = [
        LogEntry("2026-06-17T10:05:00", "LOGIN_SUCCESS", "bob", "192.168.1.15"),
        LogEntry("2026-06-17T10:00:00", "LOGIN_FAILED", "bob", "192.168.1.15"),
        LogEntry("2026-06-17T10:01:00", "LOGIN_FAILED", "bob", "192.168.1.15"),
        LogEntry("2026-06-17T10:02:00", "LOGIN_FAILED", "bob", "192.168.1.15"),
        LogEntry("2026-06-17T10:03:00", "LOGIN_FAILED", "bob", "192.168.1.15"),
        LogEntry("2026-06-17T10:04:00", "LOGIN_FAILED", "bob", "192.168.1.15"),
    ]

    alerts = detect_success_after_failure(entries)

    assert len(alerts) == 1
