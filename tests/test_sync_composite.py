"""Firepower: FMC endpoints plus the device's own CLI configuration.

Both live in one directory and one path writes it. The alternative - the main
loop modelling the CLI row while this path writes the JSON - is what produced
a device.yaml beside the JSON and a meta.yaml describing whichever ran last.
"""
import subprocess
from datetime import datetime, timezone

import pytest
import yaml

from netconfig_mirror import batch as batchlib
from netconfig_mirror.cli import _sync_composite
from netconfig_mirror.extract import CapturedConfig
from netconfig_mirror.gitops import MirrorRepo, SyncReport

FTD_CLI = """: Saved
ASA Version 9.12(4)
hostname ftd1
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.9 255.255.255.0
""" + "".join(
    f"object network SRV-{n}\n host 10.1.1.{n}\n"
    f"access-list outside_in extended permit ip any object SRV-{n}\n"
    for n in range(40)
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


def _capture(command, output, days_ago=0):
    return CapturedConfig(
        row_id="1", device_id="dev-ftd-1", command=command, output=output,
        collected_at=datetime(2026, 10, 23 - days_ago, tzinfo=timezone.utc),
        hostname="ftd1", vendor="cisco", os_version=None, device_type=None,
        serial_number=None, role=None, location="am5", collector_id="c1")


def _sync(repo, cli=None):
    fmc = [_capture("fmc_devices", '{"items": [{"name": "ftd1"}]}', days_ago=10)]
    sync = SyncReport()
    result = _sync_composite(repo, fmc[0], fmc, b"test-key", sync,
                             cli_capture=cli)
    return result, sync


def _meta(repo):
    return yaml.safe_load(
        (repo.path / "inventory/am5/ftd1/meta.yaml").read_text(encoding="utf-8"))


def test_the_cli_configuration_is_modelled_beside_the_endpoints(repo):
    result, _ = _sync(repo, _capture("show running-config", FTD_CLI))
    directory = repo.path / "inventory/am5/ftd1"

    assert result.outcome == batchlib.MIRRORED
    assert (directory / "fmc_devices.json").is_file()
    assert (directory / "running-config.yaml").is_file()
    assert (directory / "running-config.cfg").is_file()
    # Never this name: it is what the main loop writes, and two writers in one
    # directory is the thing being prevented.
    assert not (directory / "device.yaml").exists()


def test_the_model_is_the_asa_one_because_ftd_emits_asa_syntax(repo):
    _sync(repo, _capture("show running-config", FTD_CLI))
    model = yaml.safe_load((repo.path / "inventory/am5/ftd1/running-config.yaml")
                           .read_text(encoding="utf-8"))

    assert model["device"]["hostname"] == "ftd1"
    assert model["interfaces"][0]["nameif"] == "outside"
    assert len(model["objects"]) == 40


def test_both_capture_times_are_recorded_because_they_rot_separately(repo):
    """FMC endpoints 10 days old next to a CLI capture from today says the
    device is reachable and FMC collection is what broke - which the stale
    report cannot say on its own."""
    _sync(repo, _capture("show running-config", FTD_CLI))
    meta = _meta(repo)

    assert meta["source"]["collected_at"].startswith("2026-10-13")
    assert meta["running_config"]["collected_at"].startswith("2026-10-23")
    assert meta["running_config"]["modelled"] is True
    assert meta["modelled"] is True


def test_a_device_with_no_cli_row_is_unchanged(repo):
    result, _ = _sync(repo)
    meta = _meta(repo)

    assert result.outcome == batchlib.MIRRORED
    assert meta["modelled"] is False
    assert meta["running_config"] is None
    assert not (repo.path / "inventory/am5/ftd1/running-config.cfg").exists()


def test_a_credential_in_the_cli_row_still_refuses_the_device(repo):
    """This row is the only place a credential in the device's own
    configuration would surface. Being mirrored by another path must not make
    it exempt."""
    leaky = FTD_CLI + "passwd SomeLoginValue01 encrypted\nsome-vendor-key Plain1234\n"
    result, _ = _sync(repo, _capture("show running-config", leaky))

    assert result.outcome == batchlib.REDACTION_REFUSED
    assert "running-config" in result.detail


def test_an_unusable_cli_row_says_so_rather_than_vanishing(repo):
    result, _ = _sync(repo, _capture("show running-config", "ERROR: timeout\n"))

    assert result.outcome == batchlib.MIRRORED
    assert _meta(repo)["running_config"]["captured"] is False


def test_the_device_is_fresh_when_one_of_its_two_sources_is(repo):
    """The mirror held these devices' configuration from that morning while
    the alert said they had not been captured in 44 days. An alert wrong in
    that direction is how 44 days pass."""
    result, _ = _sync(repo, _capture("show running-config", FTD_CLI))

    assert result.collected_at.day == 23
    assert result.secondary_label == "ftd1 (fmc endpoints)"
    assert result.secondary_collected_at.day == 13


def test_a_stale_source_is_reported_apart_from_an_uncaptured_device():
    """Two different problems with two different owners."""
    from datetime import timedelta
    from netconfig_mirror.batch import BatchReport, DeviceResult, MIRRORED, render_summary

    now = datetime.now(timezone.utc)
    report = BatchReport()
    report.results = [DeviceResult(
        hostname="ftd1", site="am5", outcome=MIRRORED,
        collected_at=now, secondary_label="ftd1 (fmc endpoints)",
        secondary_collected_at=now - timedelta(days=44))]

    summary = render_summary(report)
    assert "not captured in over" not in summary
    assert "source(s) stale on a device that is otherwise being captured" in summary
    assert "ftd1 (fmc endpoints)" in summary
