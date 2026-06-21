import sys
import os
import pytest
from pathlib import Path

LOG_FILE = Path(__file__).parent.parent / "logs" / "sample.log"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from parser import parse_log


def test_parse_returns_list():
    entries = parse_log(LOG_FILE)

    assert isinstance(entries, list)


def test_first_entry_user():
    entries = parse_log(LOG_FILE)

    assert entries[0].user == "alice"


def test_first_entry_event():
    entries = parse_log(LOG_FILE)

    assert entries[0].event == "LOGIN_SUCCESS"


def test_first_entry_ip():
    entries = parse_log(LOG_FILE)

    assert entries[0].ip == "192.168.1.10"


def test_first_entry_timestamp():
    entries = parse_log(LOG_FILE)

    assert entries[0].timestamp == "2026-06-21T09:00:00"


def test_last_entry():
    entries = parse_log(LOG_FILE)

    assert entries[-1].user == "admin"
    assert entries[-1].event == "LOGIN_FAILED"
    assert entries[-1].ip == "203.0.113.5"


def test_missing_file_raises_error():
    with pytest.raises(FileNotFoundError):
        parse_log("logs/fake.log")
