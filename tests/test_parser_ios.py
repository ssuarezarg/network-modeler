from netconfig_mirror.parsers.ios import parse

CONFIG = """version 15.5
hostname LAB-R1
!
vrf definition CUSTOMER-A
 rd 65000:100
 description Customer A L3VPN
 address-family ipv4
  route-target export 65000:100
  route-target import 65000:100
 exit-address-family
!
interface GigabitEthernet0/0
 description UPLINK-TO-CORE
 vrf forwarding CUSTOMER-A
 ip address 10.5.76.1 255.255.255.0
 ip helper-address 10.9.9.9
 standby 10 ip 10.5.76.254
!
interface GigabitEthernet0/10
 description SPARE
 shutdown
!
interface Vlan20
 ip address 192.168.20.1 255.255.255.0
!
vlan 20
 name USERS
!
router ospf 1
 router-id 1.1.1.1
 passive-interface GigabitEthernet0/10
 network 10.5.76.0 0.0.0.255 area 0
!
router bgp 65001
 bgp router-id 1.1.1.1
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 description PEER-CORE
 neighbor 10.0.0.2 password <redacted:aabbccdd>
 !
 address-family ipv4 vrf CUSTOMER-A
  neighbor 172.16.0.1 remote-as 65100
  neighbor 172.16.0.1 description CUSTOMER-CE
 exit-address-family
!
ip route 0.0.0.0 0.0.0.0 10.5.76.254
ip route vrf CUSTOMER-A 192.168.0.0 255.255.0.0 172.16.0.1
!
ip access-list extended MGMT-IN
 permit tcp any any eq 22
 deny ip any any
!
ntp server 10.1.1.1
logging host 10.2.2.2
snmp-server community <redacted:11223344> RO
username netops privilege 15 secret 9 <redacted:55667788>
"""


def _model():
    model, _ = parse(CONFIG, platform="iosxe", os_version="15.5")
    return model


def test_device_identity():
    device = _model().device
    assert device.hostname == "LAB-R1"
    assert device.platform == "iosxe"


def test_vrf_with_route_targets():
    vrf = _model().vrfs[0]
    assert vrf.name == "CUSTOMER-A"
    assert vrf.rd == "65000:100"
    assert vrf.import_targets == ["65000:100"]
    assert vrf.export_targets == ["65000:100"]


def test_interface_attributes():
    interfaces = {i.name: i for i in _model().interfaces}
    uplink = interfaces["GigabitEthernet0/0"]
    assert uplink.description == "UPLINK-TO-CORE"
    assert uplink.vrf == "CUSTOMER-A"
    assert uplink.ipv4 == ["10.5.76.1 255.255.255.0"]
    assert uplink.helper_addresses == ["10.9.9.9"]
    assert uplink.hsrp_groups == ["10"]
    assert uplink.enabled is True


def test_shutdown_interface_is_marked_disabled():
    interfaces = {i.name: i for i in _model().interfaces}
    assert interfaces["GigabitEthernet0/10"].enabled is False


def test_interfaces_sort_numerically_not_lexically():
    """Gi0/2 must precede Gi0/10. String ordering would reverse them and produce
    a reordering diff on a device that never changed."""
    names = [i.name for i in _model().interfaces]
    assert names.index("GigabitEthernet0/0") < names.index("GigabitEthernet0/10")


def test_bgp_neighbors_including_vrf_address_family():
    bgp = _model().bgp
    assert bgp.asn == "65001"
    peers = {(n.vrf, n.peer): n for n in bgp.neighbors}
    assert peers[(None, "10.0.0.2")].remote_as == "65002"
    assert peers[(None, "10.0.0.2")].description == "PEER-CORE"
    # The neighbor inside `address-family ipv4 vrf CUSTOMER-A` must be attributed
    # to that VRF, not to the global table.
    assert peers[("CUSTOMER-A", "172.16.0.1")].remote_as == "65100"


def test_bgp_authentication_is_recorded_as_presence_only():
    """The value is a redaction token by the time the parser sees it; recording
    the flag is useful, recording the token would not be."""
    bgp = _model().bgp
    peer = next(n for n in bgp.neighbors if n.peer == "10.0.0.2")
    assert peer.authenticated is True
    assert "redacted" not in str(peer.route_maps) + str(peer.description or "")


def test_static_routes_global_and_vrf():
    routes = _model().static_routes
    assert any(r.prefix == "0.0.0.0 0.0.0.0" and r.vrf is None for r in routes)
    assert any(r.vrf == "CUSTOMER-A" and r.next_hop == "172.16.0.1" for r in routes)


def test_ospf_process():
    ospf = _model().ospf[0]
    assert ospf.process_id == "1"
    assert ospf.router_id == "1.1.1.1"
    assert ospf.passive_interfaces == ["GigabitEthernet0/10"]


def test_access_list_entries():
    acl = _model().access_lists[0]
    assert acl.name == "MGMT-IN"
    assert acl.entry_count == 2


def test_services():
    services = _model().services
    assert services.ntp_servers == ["10.1.1.1"]
    assert services.logging_hosts == ["10.2.2.2"]
    assert services.snmp_communities == 1
    assert services.local_users == ["netops"]


def test_model_output_is_deterministic():
    import yaml
    first = yaml.safe_dump(_model().to_dict(), sort_keys=False)
    second = yaml.safe_dump(_model().to_dict(), sort_keys=False)
    assert first == second


def test_empty_sections_are_omitted_from_output():
    """An empty `bgp:` key would read as a finding rather than an absence."""
    model, _ = parse("hostname SW1\n", platform="ios")
    assert "bgp" not in model.to_dict()


def test_coverage_is_reported():
    _, doc = parse(CONFIG, platform="iosxe")
    assert doc.coverage() > 0.5
    assert doc.accounted() >= doc.coverage()
