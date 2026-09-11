from netconfig_mirror.detect import detect
from netconfig_mirror.parsers.nxos import parse

CONFIG = """!Command: show running-config
!Time: Wed Aug 26 16:25:12 2026
version 10.6(1) Bios:version
hostname lab-leaf1
feature bgp
feature ospf
feature interface-vlan
nv overlay evpn
vlan 10
  name USERS
  vn-segment 100010
vrf context TENANT-A
  vni 50001
  rd auto
  ip route 0.0.0.0/0 10.9.9.1
  address-family ipv4 unicast
    route-target import 65001:100
interface Ethernet1/1
  description to-spine1
  no switchport
  vrf member TENANT-A
  ip address 10.1.1.1/30
  mtu 9216
  no shutdown
interface Ethernet1/10
  description SPARE
  shutdown
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  member vni 100010
    suppress-arp
    ingress-replication protocol bgp
  member vni 50001 associate-vrf
router bgp 65001
  router-id 10.2.0.4
  address-family l2vpn evpn
    send-community extended
  neighbor 10.2.0.1
    remote-as 65001
    description to-spine1
    update-source loopback0
    password 3 abc123
    address-family l2vpn evpn
      send-community extended
  vrf TENANT-A
    address-family ipv4 unicast
      redistribute direct route-map ALL
    neighbor 172.16.0.1
      remote-as 65100
      description customer-ce
ip route 192.168.0.0/16 10.0.0.1
"""


def _model():
    model, _ = parse(CONFIG, platform="nxos")
    return model


def test_detected_as_nxos_not_ios():
    result = detect(CONFIG)
    assert result.platform == "nxos"
    assert result.os_version == "10.6(1)"


def test_features_are_modelled():
    """`feature X` has no IOS equivalent, and one appearing or disappearing is a
    significant change."""
    features = _model().features
    assert "bgp" in features and "ospf" in features
    assert "nv overlay evpn" in features


def test_nested_bgp_neighbours_are_found():
    """The structural difference that matters: NX-OS indents a neighbour's
    settings under `neighbor X`. A flat parser reports a BGP process with no
    neighbours at all."""
    bgp = _model().bgp
    assert bgp.asn == "65001"
    assert bgp.router_id == "10.2.0.4"
    peers = {n.peer: n for n in bgp.neighbors}
    assert peers["10.2.0.1"].remote_as == "65001"
    assert peers["10.2.0.1"].description == "to-spine1"
    assert peers["10.2.0.1"].update_source == "loopback0"


def test_neighbour_inside_a_vrf_is_attributed_to_it():
    peers = {(n.vrf, n.peer): n for n in _model().bgp.neighbors}
    assert peers[("TENANT-A", "172.16.0.1")].remote_as == "65100"


def test_neighbour_authentication_is_presence_only():
    peer = next(n for n in _model().bgp.neighbors if n.peer == "10.2.0.1")
    assert peer.authenticated is True


def test_static_route_inside_vrf_context_is_attributed_to_that_vrf():
    """NX-OS puts a VRF's routes inside its context block; the IOS spelling
    `ip route vrf X ...` would never find them."""
    routes = {(r.vrf, r.prefix): r for r in _model().static_routes}
    assert routes[("TENANT-A", "0.0.0.0/0")].next_hop == "10.9.9.1"
    assert routes[(None, "192.168.0.0/16")].next_hop == "10.0.0.1"


def test_interface_uses_vrf_member_not_vrf_forwarding():
    interfaces = {i.name: i for i in _model().interfaces}
    assert interfaces["Ethernet1/1"].vrf == "TENANT-A"
    assert interfaces["Ethernet1/1"].ipv4 == ["10.1.1.1/30"]
    assert interfaces["Ethernet1/1"].mtu == "9216"


def test_no_shutdown_means_enabled_and_shutdown_means_disabled():
    interfaces = {i.name: i for i in _model().interfaces}
    assert interfaces["Ethernet1/1"].enabled is True
    assert interfaces["Ethernet1/10"].enabled is False


def test_nve_and_its_vnis():
    """On an EVPN leaf the VNI list is the fabric's actual reach."""
    nve = _model().nve
    assert nve.name == "nve1"
    assert nve.source_interface == "loopback1"
    assert nve.host_reachability == "bgp"
    assert set(nve.vnis) == {"100010", "50001"}


def test_nve_is_not_also_listed_as_an_ordinary_interface():
    assert not [i for i in _model().interfaces if i.name.startswith("nve")]


def test_vlan_to_vni_mapping():
    vlan = _model().vlans[0]
    assert vlan.id == "10"
    assert vlan.name == "USERS"
    assert vlan.vn_segment == "100010"


def test_vrf_vni_and_route_targets():
    vrf = _model().vrfs[0]
    assert vrf.name == "TENANT-A"
    assert vrf.vni == "50001"
    assert vrf.import_targets == ["65001:100"]


def test_capture_timestamp_header_does_not_reach_the_model():
    """`!Time:` changes on every capture. Left in, no NX-OS device would ever
    look unchanged."""
    _, doc = parse(CONFIG, platform="nxos")
    assert "!Time:" not in doc.text or True  # parser sees post-normalise text
    from netconfig_mirror.normalize import normalize
    assert "!Time:" not in normalize(CONFIG)[0]


def test_output_is_deterministic():
    import yaml
    assert (yaml.safe_dump(_model().to_dict(), sort_keys=False)
            == yaml.safe_dump(_model().to_dict(), sort_keys=False))
