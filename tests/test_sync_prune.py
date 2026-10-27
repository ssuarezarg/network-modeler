"""What `sync` may delete from the mirror.

`prune` exists to remove devices that left the database. It was keyed on the
*outcome* of the run instead: only a device this run managed to model was
added to the keep-set, so a device the database still returns, whose capture
came back as the collector's own error, was removed as decommissioned.

That is not a hypothetical shape. On 2026-10-27 two devices
(`WCS-DAL3-9500-SWA`, `WCS-P10-4500-SWA`) stored 63 and 66 bytes instead of a
configuration, exactly as the UK-LD5 pair has for months. Two devices out of
ninety-seven is below the 10% landslide guard, so nothing refused the deletion
and nothing warned about it: a bad night at the collector took the modelled
configuration out of the mirror in an ordinary commit.
"""
import subprocess
from datetime import datetime, timezone

import pytest

from netconfig_mirror import cli, extract
from netconfig_mirror.extract import CapturedConfig

IOS = """version 15.5
hostname {name}
""" + "".join(
    f"interface GigabitEthernet0/{n}\n description link {n}\n"
    f" ip address 10.0.{n}.1 255.255.255.0\n no shutdown\n"
    for n in range(20)
)

# What the collector stores when the session fails: a short error string that
# is not a configuration and must never be read as one.
COLLECTOR_ERROR = "ERROR: Pattern not detected: 'EDGE-SWA#' in output.\n"


def _capture(name: str, output: str) -> CapturedConfig:
    return CapturedConfig(
        row_id=f"row-{name}", device_id=f"dev-{name}",
        command="show running-config", output=output,
        collected_at=datetime(2026, 10, 27, 3, 0, tzinfo=timezone.utc),
        hostname=name, vendor="cisco_ios", os_version="15.5",
        device_type="router", serial_number=None, role=None,
        location="dal3", collector_id="c1")


@pytest.fixture
def mirror(tmp_path):
    path = tmp_path / "mirror"
    path.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"],
                   cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    return path


def _run(monkeypatch, mirror, tmp_path, captures):
    key_file = tmp_path / "key"
    key_file.write_bytes(b"0123456789abcdef")

    monkeypatch.setattr(extract, "connect", lambda dsn: _Connection())
    monkeypatch.setattr(extract, "fetch",
                        lambda connection, **kw: list(captures))
    monkeypatch.setattr(extract, "fetch_composite", lambda connection, **kw: {})

    return cli.main(["sync", "--repo", str(mirror), "--key-file", str(key_file),
                     "--out", str(tmp_path / "out")])


class _Connection:
    def close(self):
        pass


def test_a_device_whose_capture_failed_is_not_pruned(monkeypatch, mirror, tmp_path):
    # Ten devices so that losing one stays under the landslide guard, which is
    # the case that matters: a handful of bad captures is refused by nothing.
    good = [_capture(f"r{n}", IOS.format(name=f"r{n}")) for n in range(1, 11)]
    assert _run(monkeypatch, mirror, tmp_path, good) == cli.EXIT_OK
    assert (mirror / "inventory/dal3/r10/device.yaml").is_file()

    # Same estate, one bad capture. The device is still in the database.
    broken = good[:-1] + [_capture("r10", COLLECTOR_ERROR)]
    assert _run(monkeypatch, mirror, tmp_path, broken) == cli.EXIT_BATCH_ATTENTION
    assert (mirror / "inventory/dal3/r10/device.yaml").is_file(), (
        "a collector error deleted the device's modelled configuration")


def test_a_device_that_left_the_database_is_still_pruned(monkeypatch, mirror, tmp_path):
    """The keep-set is every device the database returns - not every device."""
    both = [_capture(f"r{n}", IOS.format(name=f"r{n}")) for n in range(1, 11)]
    assert _run(monkeypatch, mirror, tmp_path, both) == cli.EXIT_OK

    assert _run(monkeypatch, mirror, tmp_path, both[:-1]) == cli.EXIT_OK
    assert not (mirror / "inventory/dal3/r10").exists()
