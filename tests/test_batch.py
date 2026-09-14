from datetime import datetime, timedelta, timezone

from netconfig_mirror.batch import (
    ERROR,
    NO_PARSER,
    OK,
    REDACTION_REFUSED,
    TOO_SMALL,
    BatchReport,
    DeviceResult,
    render_summary,
    should_attempt,
)
from netconfig_mirror.extract import CapturedConfig

NOW = datetime.now(timezone.utc)


def _result(hostname, outcome, **kw):
    return DeviceResult(hostname=hostname, site="dc4", outcome=outcome, **kw)


def _capture(output):
    return CapturedConfig(
        row_id="r", device_id="d", command="show running-config", output=output,
        collected_at=NOW, hostname="r1", vendor="cisco_ios", os_version="17.3",
        device_type="router", serial_number="S", role="edge",
        location="DC4", collector_id="pureip-dc4",
    )


def test_a_tiny_capture_is_its_own_outcome_not_a_parser_failure():
    """A 65-byte error string handed to the parser surfaces as 'platform
    unknown', which reads like an unsupported device rather than a collector
    fault. They need different people to act."""
    attempt, detail = should_attempt(_capture("% Invalid input detected\n"))
    assert not attempt
    assert "bytes" in detail


def test_a_real_configuration_is_attempted():
    assert should_attempt(_capture("hostname r1\n" * 500))[0]


def test_known_platform_gaps_do_not_demand_attention():
    """Firepower and IOS-XR are accepted gaps. Failing every nightly run over
    them would train people to ignore the exit code."""
    report = BatchReport(results=[_result("fw1", NO_PARSER), _result("r1", OK)])
    assert not report.needs_attention


def test_a_redaction_refusal_demands_attention():
    report = BatchReport(results=[_result("r1", REDACTION_REFUSED), _result("r2", OK)])
    assert report.needs_attention


def test_a_tiny_capture_demands_attention():
    assert BatchReport(results=[_result("r1", TOO_SMALL)]).needs_attention


def test_an_unexpected_error_demands_attention():
    assert BatchReport(results=[_result("r1", ERROR)]).needs_attention


def test_an_all_clear_run_demands_nothing():
    assert not BatchReport(results=[_result("r1", OK), _result("r2", OK)]).needs_attention


def test_coverage_is_averaged_per_platform():
    report = BatchReport(results=[
        _result("a", OK, platform="ios", modelled_pct=60.0, accounted_pct=99.0),
        _result("b", OK, platform="ios", modelled_pct=70.0, accounted_pct=100.0),
        _result("c", OK, platform="nxos", modelled_pct=80.0, accounted_pct=100.0),
    ])
    coverage = report.coverage_by_platform()
    assert coverage["ios"][0] == 2
    assert coverage["ios"][1] == 65.0
    assert coverage["nxos"][0] == 1


def test_failed_devices_are_excluded_from_coverage_averages():
    report = BatchReport(results=[
        _result("a", OK, platform="ios", modelled_pct=60.0, accounted_pct=99.0),
        _result("b", NO_PARSER, platform="asa"),
    ])
    assert set(report.coverage_by_platform()) == {"ios"}


def test_summary_names_the_devices_that_failed():
    report = BatchReport(results=[
        _result("rtr2", TOO_SMALL, detail="65 bytes"), _result("r1", OK)])
    out = render_summary(report)
    assert "rtr2" in out and "65 bytes" in out


def test_summary_points_a_redaction_refusal_upstream():
    report = BatchReport(results=[_result("r1", REDACTION_REFUSED, detail="x")])
    out = render_summary(report)
    assert "sanitiser" in out


def test_stale_devices_are_listed():
    old = _result("sc-l3-sw", OK, platform="ios", modelled_pct=60.0,
                  accounted_pct=99.0, collected_at=NOW - timedelta(days=33))
    out = render_summary(BatchReport(results=[old]))
    assert "sc-l3-sw" in out and "33d" in out


def test_a_fresh_device_is_not_listed_as_stale():
    fresh = _result("r1", OK, platform="ios", modelled_pct=60.0,
                    accounted_pct=99.0, collected_at=NOW)
    assert not fresh.is_stale


def test_colliding_devices_are_distinguishable_in_the_output():
    """Two colliding devices printed as two identical lines look exactly like
    the silent overwrite the suffix exists to prevent."""
    from netconfig_mirror.layout import device_path, find_collisions

    first = CapturedConfig(
        row_id="r1", device_id="aaaaaaaa1111", command="show running-config",
        output="x", collected_at=NOW, hostname="Kernel", vendor="cisco_nxos",
        os_version="9.3", device_type="switch", serial_number="S", role="",
        location="CLL", collector_id="pureip-dc4")
    second = CapturedConfig(**{**first.__dict__, "row_id": "r2",
                               "device_id": "bbbbbbbb2222"})

    collisions = find_collisions([first, second])
    assert device_path(first, collisions) != device_path(second, collisions)


def test_an_acknowledged_device_does_not_demand_attention():
    """Two devices in this estate store 65-byte error strings every single
    night. Once raised with whoever owns the collector, repeating it daily is
    noise — and an alert that fires every night gets muted."""
    report = BatchReport(
        results=[_result("UK-LD5-R316-RTR1", TOO_SMALL, detail="65 bytes")],
        acknowledged={"UK-LD5-R316-RTR1"})
    assert not report.needs_attention


def test_acknowledging_one_device_does_not_silence_another():
    """The acknowledgement is per device, so a new failure still trips it."""
    report = BatchReport(
        results=[_result("UK-LD5-R316-RTR1", TOO_SMALL),
                 _result("dc4-edge-r1", REDACTION_REFUSED)],
        acknowledged={"UK-LD5-R316-RTR1"})
    assert report.needs_attention


def test_acknowledged_devices_are_still_reported():
    """Suppressed from the exit code, not from the output."""
    report = BatchReport(results=[_result("rtr1", TOO_SMALL, detail="65 bytes")],
                         acknowledged={"rtr1"})
    out = render_summary(report)
    assert "rtr1" in out and "acknowledged" in out


def test_a_missing_acknowledgement_file_acknowledges_nothing(tmp_path):
    """An unreadable suppression list must never silently suppress."""
    from netconfig_mirror.batch import load_acknowledged

    assert load_acknowledged(tmp_path / "absent.txt") == set()


def test_acknowledgement_file_ignores_comments_and_blanks(tmp_path):
    from netconfig_mirror.batch import load_acknowledged

    path = tmp_path / "ack.txt"
    path.write_text("# known bad, raised 2026-09-12\n\nUK-LD5-R316-RTR1\nrtr2  # ditto\n")
    assert load_acknowledged(path) == {"UK-LD5-R316-RTR1", "rtr2"}
