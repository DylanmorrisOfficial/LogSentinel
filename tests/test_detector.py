import pytest
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import detect_brute_force
from models import LogEntry


def test_medium_severity():
    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "Medium"


def test_high_severity():

    entries = []

    for i in range(10):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "High"


def test_critical_severity():

    entries = []

    for i in range(20):
        entries.append(
            LogEntry(f"2026-06-17T10:{i:02}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 1
    assert alerts[0].severity == "Critical"


def test_below_threshold():

    entries = []

    for i in range(4):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 0


def test_outside_time_window():

    entries = []

    for i in range(5):
        entries.append(
            LogEntry(
                f"2026-06-17T10:0{i * 2}:00", "LOGIN_FAILED", "bob", "192.168.1.15"
            )
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 0


def test_multiple_attackers():

    entries = []

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T10:0{i}:00", "LOGIN_FAILED", "bob", "192.168.1.15")
        )

    for i in range(5):
        entries.append(
            LogEntry(f"2026-06-17T11:0{i}:00", "LOGIN_FAILED", "admin", "192.168.1.20")
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 2


def test_ignore_successful_logins():

    entries = []

    for i in range(10):
        entries.append(
            LogEntry(f"2026-06-17T10:0i{i}:00", "LOGIN_SUCCESS", "bob", "192.168.1.15")
        )

    alerts = detect_brute_force(entries)

    assert len(alerts) == 0
