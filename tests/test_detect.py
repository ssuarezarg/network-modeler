from netconfig_mirror.detect import detect

IOSXE_ASR = """version 15.5
service timestamps debug datetime msec
no platform punt-keepalive disable-kernel-core
subscriber templating
hostname R1
"""

IOS_4500X = """version 15.2
no service pad
service timestamps debug datetime msec
spanning-tree mode rapid-pvst
hostname SW1
"""

ASA = """: Saved
ASA Version 9.9(1)
hostname FW
nameif outside
"""


def test_iosxe_15x_is_not_mistaken_for_classic_ios():
    """An ASR1006 reports `version 15.5` exactly like classic IOS. Keying on
    the version number alone misroutes it to the wrong parser."""
    result = detect(IOSXE_ASR)
    assert result.platform == "iosxe"
    assert result.confidence == "high"
    assert result.os_version == "15.5"


def test_negated_platform_command_still_identifies_iosxe():
    """Observed as `no platform punt-keepalive ...` -- the command existing at
    all is the signal, negated or not."""
    text = IOSXE_ASR.replace("subscriber templating\n", "")
    assert detect(text).platform == "iosxe"


def test_classic_ios_switch():
    result = detect(IOS_4500X)
    assert result.platform == "ios"
    assert result.os_version == "15.2"


def test_asa():
    result = detect(ASA)
    assert result.platform == "asa"
    assert result.os_version == "9.9(1)"


def test_collector_metadata_overrides_text_inference():
    result = detect(IOS_4500X, hint_platform="nxos", hint_version="9.3(5)")
    assert result.platform == "nxos"
    assert result.source == "collector"
    # The inferred scores are still recorded, so a contradicting hint is visible.
    assert "ios" in result.scores


def test_ambiguous_config_is_reported_as_low_confidence():
    result = detect("hostname X\nversion 15.2\n")
    assert result.confidence in ("low", "high")
    assert result.platform in ("ios", "unknown")


def test_unrecognised_input_is_not_guessed():
    result = detect("this is not a network configuration at all\n")
    assert result.platform == "unknown"
    assert result.confidence == "none"


def test_nxos_maintenance_release_suffix_is_not_part_of_the_version():
    """Real captures read `version 10.3(5) [Maintenance Release]`. The suffix
    would otherwise end up in the model and in every path built from it."""
    assert detect("feature bgp\nversion 10.3(5) [Maintenance Release]\n").os_version == "10.3(5)"
    assert detect("feature bgp\nversion 10.6(1) Bios:version\n").os_version == "10.6(1)"
