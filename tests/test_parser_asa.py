"""ASA parser.

The fixture follows the shape of the LAC1 firewall as its command census
reported it: a VPN head-end that also filters. The assertions are about the
things that only matter on this platform - `nameif` as the join key, objects
as the vocabulary of the policy, and a crypto map assembled from six separate
lines.
"""
from netconfig_mirror.parsers import asa

CONFIG = """: Saved
ASA Version 9.9(1)
hostname fw1
enable password [OMITTED_BY_SANITIZER] pbkdf2
names
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0 standby 203.0.113.3
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
 shutdown
object network SERVERS
 subnet 10.1.0.0 255.255.255.0
 description server range
object network WEB1
 host 10.1.0.10
object service HTTPS
 service tcp destination eq 443
object-group network REMOTE-SITES
 description partner networks
 network-object object WEB1
 network-object 10.2.0.0 255.255.0.0
object-group network NESTED
 group-object REMOTE-SITES
access-list outside_cryptomap extended permit ip object SERVERS object-group REMOTE-SITES
access-list outside_access_in extended permit tcp any object WEB1 eq 443
access-list outside_access_in extended deny ip any any
access-group outside_access_in in interface outside
nat (inside,outside) source static SERVERS SERVERS destination static REMOTE-SITES REMOTE-SITES
nat (inside,outside) after-auto source dynamic any interface
route outside 0.0.0.0 0.0.0.0 203.0.113.1 1
route inside 10.9.0.0 255.255.0.0 10.1.0.254 1
crypto ipsec ikev1 transform-set ESP-AES256-SHA esp-aes-256 esp-sha-hmac
crypto map outside_map 10 match address outside_cryptomap
crypto map outside_map 10 set peer 198.51.100.7
crypto map outside_map 10 set ikev1 transform-set ESP-AES256-SHA
crypto map outside_map 10 set pfs group5
crypto map outside_map 10 set security-association lifetime seconds 28800
crypto map outside_map interface outside
crypto ikev1 enable outside
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha
 group 5
 lifetime 86400
tunnel-group 198.51.100.7 type ipsec-l2l
tunnel-group 198.51.100.7 ipsec-attributes
 ikev1 pre-shared-key <redacted:abcd1234>
tunnel-group 198.51.100.99 type ipsec-l2l
tunnel-group 198.51.100.99 ipsec-attributes
 ikev1 pre-shared-key <redacted:bbbb2222>
logging host inside 10.1.0.50
interface Tunnel1
 nameif aws-tunnel-1
 ip address 169.254.10.2 255.255.255.252
 tunnel source interface outside
 tunnel destination 198.51.100.201
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile ipsec-vpn-aws-0
crypto ipsec profile ipsec-vpn-aws-0
 set ikev1 transform-set ESP-AES256-SHA
 set pfs group2
 set security-association lifetime seconds 3600
crypto ipsec profile UNUSED-PROFILE
 set ikev2 ipsec-proposal AES256
crypto ipsec security-association pmtu-aging infinite
crypto isakmp identity address
dynamic-access-policy-record DfltAccessPolicy
"""


def _model():
    model, _ = asa.parse(CONFIG, platform="asa", os_version="9.9(1)")
    return model


def _doc():
    _, doc = asa.parse(CONFIG, platform="asa")
    return doc


def test_nameif_is_captured_because_everything_else_refers_to_it():
    interfaces = {i.name: i for i in _model().interfaces}

    assert interfaces["GigabitEthernet0/0"].nameif == "outside"
    assert interfaces["GigabitEthernet0/0"].security_level == "0"
    assert interfaces["GigabitEthernet0/0"].standby_ip == "203.0.113.3"
    assert interfaces["GigabitEthernet0/1"].enabled is False


def test_objects_carry_their_kind_and_value():
    objects = {o.name: o for o in _model().objects}

    assert (objects["SERVERS"].kind, objects["SERVERS"].value) == (
        "subnet", "10.1.0.0 255.255.255.0")
    assert objects["WEB1"].kind == "host"
    assert objects["HTTPS"].kind == "service"


def test_an_object_group_records_its_members_and_what_uses_it():
    groups = {g.name: g for g in _model().object_groups}

    assert groups["REMOTE-SITES"].member_count == 2
    assert groups["REMOTE-SITES"].description == "partner networks"
    assert "access-list outside_cryptomap" in groups["REMOTE-SITES"].referenced_by
    # Nested groups: a group used only by another group is still referenced.
    assert "object-group NESTED" in groups["REMOTE-SITES"].referenced_by


def test_an_object_used_only_inside_a_group_is_still_referenced():
    objects = {o.name: o for o in _model().objects}

    assert sorted(objects["WEB1"].referenced_by) == [
        "access-list outside_access_in", "object-group REMOTE-SITES"]


def test_access_lists_are_assembled_from_one_line_per_entry():
    """Unlike IOS, where the entries are children of a block."""
    acls = {a.name: a for a in _model().access_lists}

    assert acls["outside_access_in"].entry_count == 2
    assert acls["outside_access_in"].type == "extended"


def test_where_an_access_list_is_applied():
    """An ACL in no access-group filters nothing, and neither the ACL nor the
    interface says so on its own."""
    groups = _model().access_groups

    assert len(groups) == 1
    assert (groups[0].access_list, groups[0].direction, groups[0].interface) == (
        "outside_access_in", "in", "outside")


def test_nat_keeps_its_interface_pair_and_section():
    rules = _model().nat

    assert rules[0].source_interface == "inside"
    assert rules[0].destination_interface == "outside"
    assert rules[0].kind == "static"
    assert rules[1].section == "after-auto"
    assert rules[1].kind == "dynamic"


def test_a_route_names_its_egress_interface_not_a_vrf():
    routes = _model().static_routes

    assert routes[0].interface == "outside"
    assert routes[0].vrf is None


def test_a_crypto_map_entry_is_assembled_from_six_separate_lines():
    """The ASA writes one `crypto map NAME SEQ ...` per setting, so a single
    tunnel is spread across the file and reads as nothing in particular until
    it is put back together."""
    crypto_map = _model().vpn.crypto_maps[0]

    assert crypto_map.name == "outside_map"
    assert crypto_map.interface == "outside"
    assert len(crypto_map.entries) == 1
    entry = crypto_map.entries[0]
    assert entry.peers == ["198.51.100.7"]
    assert entry.match_address == "outside_cryptomap"
    assert entry.ikev1_transform_sets == ["ESP-AES256-SHA"]
    assert entry.pfs == "group5"
    assert entry.lifetime == "28800"


def test_a_tunnel_group_records_that_a_key_exists_not_the_key():
    groups = {g.name: g for g in _model().vpn.tunnel_groups}

    assert groups["198.51.100.7"].has_pre_shared_key is True
    assert groups["198.51.100.7"].type == "ipsec-l2l"
    assert "abcd1234" not in str(groups["198.51.100.7"])


def test_a_peer_no_crypto_map_points_at_is_visible():
    """The finding this whole section exists to make possible: a tunnel-group
    configured with a key that no crypto map ever uses. The tunnel does not
    come up and nothing reports it."""
    groups = {g.name: g for g in _model().vpn.tunnel_groups}

    assert groups["198.51.100.7"].referenced_by == ["crypto map outside_map 10"]
    assert groups["198.51.100.99"].referenced_by == []


def test_ike_policy_keeps_both_spellings_of_the_integrity_field():
    """ikev1 calls it `hash`, ikev2 calls it `integrity`."""
    policy = _model().vpn.ike_policies[0]

    assert (policy.version, policy.priority) == ("ikev1", "10")
    assert policy.integrity == "sha"
    assert policy.authentication == "pre-share"


def test_everything_in_the_fixture_is_accounted_for():
    doc = _doc()

    assert doc.unconsumed_summary() == []
    assert doc.accounted() == 1.0


def test_a_route_based_tunnel_keeps_its_vpn_configuration():
    """A VTI carries its whole VPN on the interface rather than in a crypto
    map. Consuming the interface block without reading these lines lost the
    tunnel while reporting those lines as modelled."""
    tunnel = [i for i in _model().interfaces if i.name == "Tunnel1"][0]

    assert tunnel.tunnel_source == "interface outside"
    assert tunnel.tunnel_destination == "198.51.100.201"
    assert tunnel.tunnel_mode == "ipsec ipv4"
    assert tunnel.tunnel_protection == "ipsec-vpn-aws-0"


def test_an_ipsec_profile_knows_which_tunnel_uses_it():
    profiles = {p.name: p for p in _model().vpn.ipsec_profiles}

    assert profiles["ipsec-vpn-aws-0"].pfs == "group2"
    assert profiles["ipsec-vpn-aws-0"].lifetime == "3600"
    assert profiles["ipsec-vpn-aws-0"].referenced_by == ["interface Tunnel1"]


def test_a_profile_no_tunnel_applies_is_visible():
    """The route-based equivalent of a tunnel-group no crypto map points at."""
    profiles = {p.name: p for p in _model().vpn.ipsec_profiles}

    assert profiles["UNUSED-PROFILE"].referenced_by == []


def test_a_route_based_peer_is_not_reported_as_an_unused_tunnel_group():
    """A VTI reaches its peer through `tunnel destination`, never through a
    crypto map, but still authenticates against the tunnel-group named after
    that peer. Counting only crypto map peers reports every VTI peer as unused."""
    model, _ = asa.parse(CONFIG + (
        "tunnel-group 198.51.100.201 type ipsec-l2l\n"
        "tunnel-group 198.51.100.201 ipsec-attributes\n"
        " ikev1 pre-shared-key <redacted:cccc3333>\n"), platform="asa")
    groups = {g.name: g for g in model.vpn.tunnel_groups}

    assert groups["198.51.100.201"].referenced_by == ["interface Tunnel1"]
