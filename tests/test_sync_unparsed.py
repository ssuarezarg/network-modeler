"""Mirroring a configuration no parser covers.

An ASA used to leave nothing in the mirror at all - `_sync_one` returned
before writing, so the redacted text it had just produced was discarded and
nobody could see that the device had changed, or what it held. Versioning the
text is most of the value and needs no parser.
"""
import subprocess
from datetime import datetime, timezone

import pytest
import yaml

from netconfig_mirror import batch as batchlib
from netconfig_mirror.analysis import load_devices
from netconfig_mirror.cli import _sync_one
from netconfig_mirror.extract import CapturedConfig
from netconfig_mirror.gitops import MirrorRepo, SyncReport

# Both fixtures are padded past the threshold below which a capture is read as
# a collector error rather than a configuration.
ASA = """: Saved
ASA Version 9.9(1)
hostname fw1
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 10.0.0.1 255.255.255.0
failover key SomeFailoverKey2026
""" + "".join(
    f"object network SRV-{n}\n host 10.1.1.{n}\n"
    f"access-list outside_in extended permit ip any object SRV-{n}\n"
    for n in range(40)
)

IOS = """version 15.5
hostname r1
""" + "".join(
    f"interface GigabitEthernet0/{n}\n description link {n}\n"
    f" ip address 10.0.{n}.1 255.255.255.0\n no shutdown\n"
    for n in range(20)
)


def _git(path, *args):
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "mirror"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    (path / ".keep").write_text("")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "init")
    return MirrorRepo(path)


class _Args:
    platform = None


def _capture(output, hostname="fw1"):
    return CapturedConfig(
        row_id="1", device_id="dev-asa-1", command="show running-config",
        output=output, collected_at=datetime(2026, 10, 23, tzinfo=timezone.utc),
        hostname=hostname, vendor=None, os_version=None, device_type=None,
        serial_number=None, role=None, location="lac1", collector_id="c1")


def _sync(repo, output, relative="inventory/lac1/fw1"):
    sync = SyncReport()
    result = _sync_one(repo, _capture(output), b"test-key", _Args(), relative, sync)
    return result, sync


def test_an_unparsed_configuration_is_mirrored_as_text(repo):
    result, sync = _sync(repo, ASA)

    assert result.outcome == batchlib.MIRRORED_RAW
    assert result.platform == "asa"
    assert (repo.path / "inventory/lac1/fw1/raw.cfg").is_file()
    assert sync.written == ["inventory/lac1/fw1"]


def test_no_model_is_invented_for_it(repo):
    """A device.yaml here would be an empty model that looks valid."""
    _sync(repo, ASA)

    assert not (repo.path / "inventory/lac1/fw1/device.yaml").exists()
    assert load_devices(repo.path) == []


def test_its_metadata_says_it_is_not_modelled(repo):
    _sync(repo, ASA)
    meta = yaml.safe_load(
        (repo.path / "inventory/lac1/fw1/meta.yaml").read_text(encoding="utf-8"))

    assert meta["modelled"] is False
    assert meta["platform"] == "asa"
    assert meta["source"]["device_id"] == "dev-asa-1"


def test_the_mirrored_text_is_redacted(repo):
    """It reaches a Git-tracked path, so it goes through redaction exactly as a
    modelled configuration does."""
    _sync(repo, ASA)
    written = (repo.path / "inventory/lac1/fw1/raw.cfg").read_text(encoding="utf-8")

    assert "SomeFailoverKey2026" not in written
    assert "failover key <redacted:" in written


def test_an_unchanged_capture_does_not_rewrite_metadata(repo):
    """Same contract as the modelled path: provenance moves only beside a real
    content change, so an unchanged device stays untouched in the diff."""
    _sync(repo, ASA)
    repo.commit("first")

    _, sync = _sync(repo, ASA)
    assert sync.changed == []


def test_a_supported_platform_still_takes_the_modelled_path(repo):
    result, _ = _sync(repo, IOS, relative="inventory/dc4/r1")

    assert result.outcome == batchlib.OK
    assert (repo.path / "inventory/dc4/r1/device.yaml").is_file()


def test_a_device_mirrored_by_another_path_is_not_overwritten(repo):
    """A Firepower has a `show running-config` row as well as its FMC
    endpoints. While an unparsable platform was discarded that row was
    harmless; mirroring it as text wrote a raw.cfg into the directory the JSON
    path owns and overwrote the meta.yaml it had written there."""
    relative = "inventory/am5/am5-fw1"
    repo.write_files(relative, {"fmc_devices.json": "{}\n"})
    repo.write_meta(relative, yaml.safe_dump({"platform": "firepower"}))

    sync = SyncReport()
    result = _sync_one(repo, _capture(ASA), b"test-key", _Args(), relative,
                       sync, allow_raw=False)

    assert result.outcome == batchlib.NO_PARSER
    assert not (repo.path / relative / "raw.cfg").exists()
    meta = yaml.safe_load((repo.path / relative / "meta.yaml").read_text())
    assert meta == {"platform": "firepower"}
    assert sync.written == []
