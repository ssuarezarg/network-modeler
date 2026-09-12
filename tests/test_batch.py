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
