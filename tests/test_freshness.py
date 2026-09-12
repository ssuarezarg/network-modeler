from datetime import datetime, timedelta, timezone

from netconfig_mirror.freshness import (
    DEFAULT_STALE_AFTER,
    assess,
    render_report,
)
from netconfig_mirror.extract import CapturedConfig

NOW = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)


def _capture(hostname: str, days_ago: float) -> CapturedConfig:
    return CapturedConfig(
        row_id="r", device_id="d-" + hostname, command="show running-config",
        output="hostname x\n", collected_at=NOW - timedelta(days=days_ago),
        hostname=hostname, vendor="cisco_ios", os_version="15.5",
        device_type="router", serial_number="S", role="edge",
        location="LAC1", collector_id="wcs",
    )


def test_recent_capture_is_fresh():
    result = assess([_capture("r1", days_ago=1)], now=NOW)
    assert result[0].state == "fresh"


def test_abandoned_device_is_flagged_stale():
    """A collector that stopped leaves its devices frozen in the viewer with
    nothing marking them. This is the only signal that it happened."""
    result = assess([_capture("r1", days_ago=90)], now=NOW)
    assert result[0].is_stale


def test_threshold_boundary():
    just_inside = assess([_capture("r1", days_ago=6.9)], now=NOW)
    just_outside = assess([_capture("r1", days_ago=7.1)], now=NOW)
    assert not just_inside[0].is_stale
    assert just_outside[0].is_stale


def test_report_does_not_change_when_nothing_changes():
    """The naive version of this report embeds 'last seen N hours ago' and
    churns the repo on every single run, for every device, forever."""
    captures = [_capture("r1", days_ago=1), _capture("r2", days_ago=30)]
    first = render_report(assess(captures, now=NOW))
    later = render_report(assess(captures, now=NOW + timedelta(hours=6)))
    assert first == later


def test_a_new_capture_of_healthy_devices_does_not_change_the_report():
    """The case that actually happens: every run brings fresh captures with new
    timestamps. Tabulating every device would move every row, producing a commit
    every day for a network that did not change."""
    monday = [_capture("r1", days_ago=1), _capture("r2", days_ago=2)]
    tuesday = [_capture("r1", days_ago=0.1), _capture("r2", days_ago=0.2)]
    assert render_report(assess(monday, now=NOW)) == render_report(assess(tuesday, now=NOW))


def test_healthy_devices_are_counted_not_listed():
    out = render_report(assess([_capture("r1", days_ago=1)], now=NOW))
    assert "r1" not in out
    assert "0 stale of 1" in out


def test_a_stale_device_is_named_with_its_last_capture_date():
    out = render_report(assess([_capture("abandoned-sw", days_ago=90)], now=NOW))
    assert "abandoned-sw" in out
    assert "1 stale of 1" in out


def test_report_changes_when_a_device_goes_stale():
    captures = [_capture("r1", days_ago=6)]
    before = render_report(assess(captures, now=NOW))
    after = render_report(assess(captures, now=NOW + timedelta(days=3)))
    assert before != after
    assert "stale" in after


def test_report_is_deterministic_for_a_given_input():
    captures = [_capture("b", days_ago=1), _capture("a", days_ago=30)]
    assert render_report(assess(captures, now=NOW)) == render_report(assess(captures, now=NOW))


def test_naive_collected_at_is_treated_as_utc():
    capture = _capture("r1", days_ago=1)
    naive = CapturedConfig(**{**capture.__dict__, "collected_at": datetime(2026, 9, 10, 12, 0)})
    assert assess([naive], now=NOW)[0].state == "fresh"
