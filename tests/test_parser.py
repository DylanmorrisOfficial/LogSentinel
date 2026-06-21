import pytest
import ipaddress
import os
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from parser import parse_log

LOG_FILE = Path(__file__).parent.parent / "logs" / "sample.log"


@pytest.fixture
def entries():
    return parse_log(LOG_FILE)


def test_parse_returns_list(entries):
    assert isinstance(entries, list)
    assert len(entries) > 0


def test_entries_have_required_structure(entries):
    entry = entries[0]

    assert hasattr(entry, "user")
    assert hasattr(entry, "event")
    assert hasattr(entry, "ip")
    assert hasattr(entry, "timestamp")


def test_ip_addresses_are_valid(entries):
    for entry in entries:
        parsed_ip = ipaddress.ip_address(entry.ip)
        assert isinstance(parsed_ip, ipaddress._BaseAddress)


def test_timestamps_are_valid_isoformat(entries):
    for entry in entries:
        parsed_time = datetime.fromisoformat(entry.timestamp)
        assert isinstance(parsed_time, datetime)


def test_first_and_last_entries(entries):
    first = entries[0]
    last = entries[-1]

    assert first.user is not None
    assert first.event is not None

    assert last.user is not None
    assert last.event is not None


def test_parser_handles_missing_file():
    with pytest.raises(FileNotFoundError):
        parse_log("logs/missing_file.log")
