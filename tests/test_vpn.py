"""The IPsec endpoint survey.

Written for a relocation question: which remote parties terminate a tunnel on
a site's equipment. A tunnel is built in one of two ways that look nothing
alike, and a survey that knows only one of them misses the other entirely.
"""
import yaml

from netconfig_mirror.analysis import load_devices
from netconfig_mirror.vpn import collect, render


def _mirror(tmp_path, doc, name="wcs-lac-asa", site="lac1"):
    directory = tmp_path / "inventory" / site / name
    directory.mkdir(parents=True)
    (directory / "device.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return load_devices(tmp_path)


FIREWALL = {
    "device": {"hostname": "WCS-LAC-ASA"},
    "interfaces": [
        {"name": "GigabitEthernet0/0", "nameif": "outside"},
        {"name": "Tunnel1", "nameif": "aws-1",
         "tunnel_destination": "3.223.167.236",
         "tunnel_protection": "ipsec-vpn-aws-0"},
        {"name": "Tunnel2", "nameif": "aws-2",
         "tunnel_destination": "34.225.122.217",
         "tunnel_protection": "ipsec-vpn-aws-1"},
    ],
    "vpn": {
        "crypto_maps": [{"name": "outside_map", "interface": "outside", "entries": [
            {"seq": "10", "peers": ["198.51.100.7"],
             "match_address": "outside_cryptomap"}]}],
        "ipsec_profiles": [{"name": "ipsec-vpn-aws-0"}, {"name": "ipsec-vpn-aws-1"}],
        "tunnel_groups": [
            {"name": "198.51.100.7", "has_pre_shared_key": True},
            {"name": "3.223.167.236", "has_pre_shared_key": True},
            {"name": "34.225.122.217", "has_pre_shared_key": True},
            {"name": "203.0.113.50", "has_pre_shared_key": True},
        ],
    },
}


def test_both_ways_of_building_a_tunnel_are_reported(tmp_path):
    """A crypto map and a tunnel interface share nothing in the configuration
    except the tunnel-group they authenticate against."""
    [device] = collect(_mirror(tmp_path, FIREWALL))
    styles = sorted(e.style for e in device.endpoints)

    assert styles == ["policy-based", "route-based", "route-based"]
    assert sorted(e.peer for e in device.endpoints) == [
        "198.51.100.7", "3.223.167.236", "34.225.122.217"]


def test_the_local_interface_is_named_for_each(tmp_path):
    """What the far end has configured as its own peer address lives on this
    interface - which is what decides whether the tunnel survives a move."""
    [device] = collect(_mirror(tmp_path, FIREWALL))
    by_peer = {e.peer: e for e in device.endpoints}

    assert by_peer["198.51.100.7"].local_interface == "outside"
    assert by_peer["3.223.167.236"].local_interface == "aws-1"


def test_a_peer_no_tunnel_reaches_is_listed_apart(tmp_path):
    """During a relocation, a peer that was decommissioned and one that was
    never wired up are the same question: does anyone still expect it?"""
    [device] = collect(_mirror(tmp_path, FIREWALL))

    assert device.unused_peers == ["203.0.113.50"]


def test_a_tunnel_with_no_tunnel_group_is_flagged(tmp_path):
    doc = {**FIREWALL, "vpn": {**FIREWALL["vpn"], "tunnel_groups": []}}
    [device] = collect(_mirror(tmp_path, doc))

    assert all(e.missing_tunnel_group for e in device.endpoints)
    assert "NO TUNNEL-GROUP" in render([device])


def test_a_profile_that_does_not_exist_is_named_in_the_line(tmp_path):
    doc = {**FIREWALL, "vpn": {**FIREWALL["vpn"], "ipsec_profiles": []}}
    [device] = collect(_mirror(tmp_path, doc))

    assert "[profile not defined]" in render([device])


def test_a_device_with_no_vpn_is_left_out(tmp_path):
    assert collect(_mirror(tmp_path, {"device": {"hostname": "r1"}})) == []


def test_the_report_ends_with_the_distinct_remote_endpoints(tmp_path):
    report = render(collect(_mirror(tmp_path, FIREWALL)))

    assert "3 distinct remote endpoint(s)" in report
    assert report.rstrip().endswith("34.225.122.217")
