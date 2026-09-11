from datetime import datetime, timedelta, timezone

from netconfig_mirror.extract import (
    FTD_COMMANDS,
    RUNNING_CONFIG_COMMANDS,
    STARTUP_CONFIG_COMMANDS,
    CapturedConfig,
    all_config_commands,
    slugify,
    watermark_with_overlap,
)


def _capture(**overrides) -> CapturedConfig:
    base = dict(
        row_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        device_id="94cce633-1e90-45c2-b349-b01c99c0b789",
        command="show running-config",
        output="hostname dc4-edge-r1\n",
        collected_at=datetime(2026, 9, 8, 3, 30, 31, tzinfo=timezone.utc),
        hostname="dc4-edge-r1",
        vendor="cisco_ios",
        os_version="17.3",
        device_type="router",
        serial_number="FCH1234ABCD",
        role="edge",
        location="LAC1 - Sala 2",
        collector_id="wcs",
    )
    base.update(overrides)
    return CapturedConfig(**base)


def test_only_commands_observed_in_the_database_are_used():
    """Juniper/Palo Alto spellings were removed after the real command census
    showed they have never been collected. Guessing them is dead code that
    reads like coverage."""
    assert all_config_commands() == ["show running-config"]


def test_startup_config_is_opt_in_and_separate():
    """Collected too (3331 rows), and worth mirroring separately: running vs
    startup divergence means the device silently reverts on reboot."""
    assert "show startup-config" in STARTUP_CONFIG_COMMANDS
    assert "show startup-config" not in all_config_commands()
    assert "show startup-config" in all_config_commands(include_startup=True)


def test_ftd_endpoints_are_not_treated_as_a_flat_config():
    """Firepower state is spread across several FMC REST endpoints, none of
    which is a running-config. Treating one as such would mirror a fragment
    and call it the device's configuration."""
    for command in FTD_COMMANDS:
        assert command not in all_config_commands(include_startup=True)


def test_command_list_is_deduplicated():
    commands = all_config_commands(include_startup=True)
    assert len(commands) == len(set(commands))
    assert RUNNING_CONFIG_COMMANDS[0] in commands


def test_unknown_command_probe_only_looks_for_config_commands():
    """~60 distinct commands exist, nearly all operational state. Reporting all
    of them would bury the one line that matters."""
    from netconfig_mirror.extract import UNKNOWN_COMMANDS

    assert "ILIKE" in UNKNOWN_COMMANDS and "config" in UNKNOWN_COMMANDS


def test_device_key_uses_hostname_for_readable_paths():
    assert _capture().device_key == "dc4-edge-r1"


def test_device_key_falls_back_to_uuid_when_hostname_is_null():
    """`devices.hostname` is nullable, so this is reachable with real data."""
    capture = _capture(hostname=None)
    assert capture.device_key.startswith("device-")
    assert capture.device_id in capture.device_key


def test_site_key_slugifies_free_text_location():
    assert _capture().site_key == "lac1-sala-2"


def test_site_key_without_location():
    assert _capture(location=None).site_key == "unassigned"


def test_slugify_never_returns_an_empty_path_segment():
    assert slugify("///") == "unnamed"
    assert slugify("") == "unnamed"


def test_watermark_steps_back_to_avoid_skipping_late_rows():
    """A strict `>` watermark permanently skips rows that land out of order.
    Re-reading is free; a missed capture is not."""
    last_run = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    assert watermark_with_overlap(last_run) == last_run - timedelta(hours=1)


def test_naive_watermark_is_treated_as_utc():
    """collected_at is TIMESTAMPTZ; comparing it against a naive datetime would
    raise or silently misbehave depending on the driver."""
    result = watermark_with_overlap(datetime(2026, 9, 8, 12, 0, 0))
    assert result.tzinfo is not None


def test_slugify_preserves_hyphens_in_hostnames():
    """Dropping them would turn `dc4-edge-r1` into `dc4edger1` and could collide
    two different devices onto one directory."""
    assert slugify("dc4-edge-r1") == "dc4-edge-r1"
    assert slugify("SITE1-ASR1006-R2") == "site1-asr1006-r2"
    assert slugify("a-b") != slugify("ab")


def test_queries_scope_by_collector_id():
    """The viewer database is multi-tenant. Without this filter the mirror would
    contain every customer it holds."""
    from netconfig_mirror.extract import LATEST_PER_DEVICE, SINCE_WATERMARK

    for sql in (LATEST_PER_DEVICE, SINCE_WATERMARK):
        assert "collector_id" in sql


def test_collector_id_filter_is_optional_but_explicit():
    """NULL means 'all tenants' -- a deliberate choice at the call site, not an
    accident of a missing parameter."""
    from netconfig_mirror.extract import LATEST_PER_DEVICE

    assert "%(collector_id)s IS NULL OR" in LATEST_PER_DEVICE
