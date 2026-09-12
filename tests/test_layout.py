from datetime import datetime, timezone

from netconfig_mirror.extract import CapturedConfig
from netconfig_mirror.layout import device_path, find_collisions, site_of


def _capture(hostname, device_id="d1", location="DC4"):
    return CapturedConfig(
        row_id="r", device_id=device_id, command="show running-config",
        output="hostname x\n", collected_at=datetime(2026, 9, 12, tzinfo=timezone.utc),
        hostname=hostname, vendor="cisco_ios", os_version="17.3",
        device_type="router", serial_number="S", role="edge",
        location=location, collector_id="pureip-dc4",
    )


def test_site_comes_from_location():
    assert site_of(_capture("dc4-edge-r1", location="DC4")) == "dc4"
    assert site_of(_capture("x", location="LD5")) == "ld5"


def test_site_falls_back_to_the_hostname_when_location_is_missing():
    assert site_of(_capture("UK-LD5-R316-SW1", location=None)) == "uk-ld5"


def test_site_of_last_resort():
    assert site_of(_capture(None, location=None)) == "unassigned"


def test_ordinary_path():
    assert device_path(_capture("dc4-edge-r1")) == "inventory/dc4/dc4-edge-r1"


def test_collision_between_two_device_ids_is_detected():
    captures = [_capture("Kernel", device_id="aaa", location="CLL"),
                _capture("Kernel", device_id="bbb", location="CLL")]
    # Paths are lower-cased: on a case-insensitive filesystem `Kernel` and
    # `kernel` would collide anyway, so normalising avoids a platform-
    # dependent difference between checkouts.
    assert find_collisions(captures) == {("cll", "kernel")}


def test_the_same_device_seen_twice_is_not_a_collision():
    captures = [_capture("sw1", device_id="aaa"), _capture("sw1", device_id="aaa")]
    assert find_collisions(captures) == set()


def test_colliding_devices_get_distinct_paths():
    """The real collision in this estate is two devices both named `Kernel`, in
    the same site and the same collector -- so nothing in the hierarchy
    separates them and the device_id has to."""
    first = _capture("Kernel", device_id="aaaaaaaa1111", location="CLL")
    second = _capture("Kernel", device_id="bbbbbbbb2222", location="CLL")
    collisions = find_collisions([first, second])
    assert device_path(first, collisions) != device_path(second, collisions)
    assert device_path(first, collisions).startswith("inventory/cll/kernel-")


def test_collision_suffix_is_stable_across_runs():
    """It is derived from device_id, so a device does not move between runs."""
    capture = _capture("Kernel", device_id="aaaaaaaa1111", location="CLL")
    collisions = {("cll", "kernel")}
    assert device_path(capture, collisions) == device_path(capture, collisions)
    assert "aaaaaaaa" in device_path(capture, collisions)


def test_a_device_without_a_collision_keeps_its_plain_path():
    collisions = {("cll", "kernel")}
    assert device_path(_capture("dc4-edge-r1"), collisions) == "inventory/dc4/dc4-edge-r1"


def test_paths_are_lower_cased():
    """A case-insensitive filesystem would treat `Kernel` and `kernel` as one
    directory, so a checkout on macOS or Windows would differ from Linux."""
    assert device_path(_capture("UK-LD5-R316-SW1", location="LD5")) == \
        "inventory/ld5/uk-ld5-r316-sw1"
