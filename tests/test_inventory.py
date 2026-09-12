from datetime import datetime, timezone

from netconfig_mirror.inventory import (
    SUSPICIOUS_CAPTURE_BYTES,
    Survey,
    datacenter_from_hostname,
    render,
)


def test_datacenter_from_hostname_handles_the_conventions_in_use():
    """Real hostnames from this estate. The site comes first, separated by `-`
    or `_`."""
    assert datacenter_from_hostname("dc4-edge-r1") == "dc4"
    assert datacenter_from_hostname("sv2-r705-l3-sw1") == "sv2"
    assert datacenter_from_hostname("am5-oob-sw1") == "am5"
    assert datacenter_from_hostname("hk1-rtr1") == "hk1"


def test_two_letter_country_prefix_is_kept_with_the_next_segment():
    """`UK` alone names a country, not a datacenter -- grouping on it would put
    London Docklands and Canary Wharf in one bucket."""
    assert datacenter_from_hostname("UK-LD5-R316-SW1") == "uk-ld5"
    assert datacenter_from_hostname("UK-CLL-L3-SW1") == "uk-cll"
    assert datacenter_from_hostname("SG-SG2-R1") == "sg-sg2"


def test_underscores_are_treated_like_hyphens():
    assert datacenter_from_hostname("SV2_R705_FW1") == "sv2"


def test_missing_hostname_yields_nothing_rather_than_guessing():
    assert datacenter_from_hostname(None) is None
    assert datacenter_from_hostname("") is None


def test_location_is_unusable_when_almost_everything_is_unset():
    survey = Survey(by_location=[("(unset)", 70), ("LAC1", 2)])
    assert not survey.location_is_usable


def test_location_is_usable_when_populated_and_varied():
    survey = Survey(by_location=[("DC4", 20), ("AM5", 15), ("SG2", 10)])
    assert survey.location_is_usable


def test_single_location_value_is_not_grouping():
    survey = Survey(by_location=[("EMEA", 72)])
    assert not survey.location_is_usable


def _capture(hostname, size):
    return (hostname, "cisco_ios", "DC4", "wcs", size,
            datetime(2026, 9, 11, tzinfo=timezone.utc))


def test_tiny_captures_are_flagged():
    """Devices reporting successful collection while storing a 65-byte error
    string exist in this estate, and nothing upstream notices."""
    survey = Survey(captures=[_capture("rtr2", 65), _capture("sw1", 97144)])
    assert [row[0] for row in survey.suspicious_captures] == ["rtr2"]


def test_threshold_excludes_genuine_small_configs():
    survey = Survey(captures=[_capture("oob-sw", SUSPICIOUS_CAPTURE_BYTES + 1)])
    assert survey.suspicious_captures == []


def test_report_calls_out_collisions_as_a_path_problem():
    survey = Survey(collisions=[("core-sw1", 2, "orgA, orgB", "DC4, AM5")])
    out = render(survey)
    assert "core-sw1" in out
    assert "directory" in out


def test_report_says_so_when_there_are_no_collisions():
    out = render(Survey(by_location=[("DC4", 5), ("AM5", 5)]))
    assert "None." in out
    # And still warns, because these tenants are organisations merging.
    assert "merging" in out
