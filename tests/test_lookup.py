"""Tests for the hostname lookup, using a fake DB-API connection.

No database is available here, so the queries themselves are unverified against
a live server -- but the branching around them is exactly where a confusing
failure would come from, and that is testable.
"""
from datetime import datetime, timezone

import pytest

from netconfig_mirror.extract import (
    AmbiguousDevice,
    DeviceNotFound,
    NoConfigCaptured,
    fetch_by_hostname,
)

COLUMNS = ["id", "device_id", "command", "output", "collected_at", "hostname",
           "vendor", "os_version", "device_type", "serial_number", "role",
           "location", "collector_id"]


def _row(hostname="R1", collector="wcs"):
    return ("row-1", "dev-1", "show running-config", "hostname R1\n",
            datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc), hostname,
            "cisco_ios", "15.5", "router", "SN1", "edge", "LAC1", collector)


class FakeCursor:
    def __init__(self, script):
        self._script = script
        self.description = None
        self._rows = []

    def execute(self, sql, params=None):
        key = "capture" if "DISTINCT ON" in sql else (
            "exists" if "FROM devices d\n WHERE lower" in sql else "similar")
        self._rows = self._script.get(key, [])
        self.description = [(name,) for name in COLUMNS]

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    def __init__(self, **script):
        self._script = script

    def cursor(self):
        return FakeCursor(self._script)

    def close(self):
        pass


def test_returns_the_latest_capture():
    capture = fetch_by_hostname(FakeConnection(capture=[_row()]), "R1")
    assert capture.hostname == "R1"
    assert capture.command == "show running-config"
    assert capture.row_id == "row-1"


def test_unknown_hostname_raises_device_not_found():
    with pytest.raises(DeviceNotFound):
        fetch_by_hostname(FakeConnection(capture=[], exists=[]), "nope")


def test_known_device_without_a_capture_is_a_different_error():
    """'No such device' and 'device exists but was never captured' are different
    problems with different fixes. Collapsing them sends people looking in the
    wrong place."""
    connection = FakeConnection(capture=[], exists=[("dev-1", "FTD-1", "cisco_ftd", "wcs")])
    with pytest.raises(NoConfigCaptured) as error:
        fetch_by_hostname(connection, "FTD-1")
    assert "fmc_" in str(error.value)


def test_same_hostname_in_two_tenants_is_ambiguous():
    """The viewer is multi-tenant; picking one silently would model the wrong
    customer's device under the right name."""
    connection = FakeConnection(capture=[_row(collector="wcs"), _row(collector="tristan")])
    with pytest.raises(AmbiguousDevice) as error:
        fetch_by_hostname(connection, "R1")
    assert "--collector-id" in str(error.value)


def test_lookup_is_case_insensitive_by_query():
    from netconfig_mirror.extract import LATEST_BY_HOSTNAME

    assert "lower(d.hostname) = lower(" in LATEST_BY_HOSTNAME


def test_connection_is_forced_read_only():
    """The role should already be SELECT-only, but a guarantee that does not
    depend on the grants being right is worth one statement."""
    import inspect

    from netconfig_mirror import extract

    assert "TRANSACTION READ ONLY" in inspect.getsource(extract.connect)


def test_nullable_parameters_carry_an_explicit_cast():
    """A parameter used only as `$n IS NULL` gives Postgres nothing to infer a
    type from: the query fails with "could not determine data type of parameter".

    Caught only by a real server -- the fake connection above never sends SQL to
    a parser -- so this guards the queries by inspection instead.
    """
    from netconfig_mirror.extract import (
        LATEST_BY_HOSTNAME,
        LATEST_PER_DEVICE,
        SINCE_WATERMARK,
    )

    for sql in (LATEST_BY_HOSTNAME, LATEST_PER_DEVICE, SINCE_WATERMARK):
        assert "%(collector_id)s IS NULL" not in sql, "uncast nullable parameter"
        assert "%(collector_id)s::text IS NULL" in sql
