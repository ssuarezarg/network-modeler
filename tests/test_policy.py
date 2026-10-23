"""Routing policy: prefix-lists and route-maps, on both platforms.

Modelled because it is what actually changes. The first real diff the mirror
produced was a hundred new prefix-list entries across six devices — and the
model saw none of it.
"""
from netconfig_mirror.parsers import ios, nxos

IOS_CONFIG = """hostname R1
!
ip prefix-list CARRIER_OUT seq 5 permit 10.1.10.100/32
ip prefix-list CARRIER_OUT seq 10 permit 10.111.0.0/16
ip prefix-list CARRIER_OUT seq 15 permit 203.0.113.0/24 le 32
ip prefix-list CARRIER_OUT seq 200 deny 0.0.0.0/0 le 32
!
ip prefix-list ORPHANED seq 5 permit 192.168.0.0/16
!
ip prefix-list WITH_GE seq 5 permit 10.0.0.0/8 ge 24 le 30
!
route-map TO-CARRIER permit 10
 match ip address prefix-list CARRIER_OUT
 set local-preference 200
!
route-map TO-CARRIER deny 20
!
route-map OTHER permit 5
 match ip address prefix-list CARRIER_OUT WITH_GE
!
router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 neighbor 10.0.0.1 route-map TO-CARRIER out
"""


def _ios():
    model, _ = ios.parse(IOS_CONFIG, platform="iosxe")
    return model


def test_prefix_list_entries_are_parsed():
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["CARRIER_OUT"].entry_count == 4
    first = lists["CARRIER_OUT"].entries[0]
    assert (first.action, first.prefix, first.seq) == ("permit", "10.1.10.100/32", "5")


def test_deny_entries_are_kept():
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["CARRIER_OUT"].entries[-1].action == "deny"


def test_ge_and_le_are_captured():
    """A prefix with le 32 matches every more-specific route inside it. Dropping
    that qualifier would make two very different policies look identical."""
    lists = {p.name: p for p in _ios().prefix_lists}
    entry = lists["WITH_GE"].entries[0]
    assert (entry.ge, entry.le) == ("24", "30")
    assert lists["CARRIER_OUT"].entries[2].le == "32"


def test_entries_are_ordered_by_sequence_not_by_prefix():
    """Sequence order is the order the device evaluates them in. Sorting by
    prefix would look tidier and misrepresent the policy."""
    seqs = [e.seq for e in {p.name: p for p in _ios().prefix_lists}["CARRIER_OUT"].entries]
    assert seqs == ["5", "10", "15", "200"]


def test_route_map_clauses_are_grouped_by_name():
    """IOS writes each clause as its own top-level block, so one route-map
    arrives as several blocks sharing a name."""
    maps = {m.name: m for m in _ios().route_maps}
    assert len(maps["TO-CARRIER"].clauses) == 2
    assert [c.seq for c in maps["TO-CARRIER"].clauses] == ["10", "20"]
    assert maps["TO-CARRIER"].clauses[1].action == "deny"


def test_match_and_set_lines_are_kept():
    maps = {m.name: m for m in _ios().route_maps}
    clause = maps["TO-CARRIER"].clauses[0]
    assert clause.match == ["ip address prefix-list CARRIER_OUT"]
    assert clause.set == ["local-preference 200"]


def test_one_match_line_can_name_several_prefix_lists():
    maps = {m.name: m for m in _ios().route_maps}
    assert maps["OTHER"].prefix_lists == ["CARRIER_OUT", "WITH_GE"]


def test_a_referenced_prefix_list_records_who_uses_it():
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["CARRIER_OUT"].referenced_by == ["route-map OTHER", "route-map TO-CARRIER"]


def test_a_prefix_list_applied_straight_to_a_neighbour_counts_as_referenced():
    """The usual shape on an edge router carrying per-customer policy: no
    route-map in between. Counting only route-maps reported 1007 of roughly
    1100 prefix-lists in this estate as inert — the tool being wrong, not the
    network."""
    config = IOS_CONFIG + """ neighbor 10.0.0.1 prefix-list ORPHANED in\n"""
    model, _ = ios.parse(config, platform="iosxe")
    lists = {p.name: p for p in model.prefix_lists}
    assert lists["ORPHANED"].referenced_by == ["neighbor 10.0.0.1"]


def test_the_direction_survives_on_the_neighbour():
    config = IOS_CONFIG + """ neighbor 10.0.0.1 prefix-list ORPHANED in\n"""
    model, _ = ios.parse(config, platform="iosxe")
    peer = next(n for n in model.bgp.neighbors if n.peer == "10.0.0.1")
    assert peer.prefix_lists == ["ORPHANED in"]


def test_an_unreferenced_prefix_list_is_visibly_inert():
    """The reason this is modelled at all. A list nothing references announces
    nothing, however many entries it holds — and on one real router nine of
    thirty were in exactly that state."""
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["ORPHANED"].entry_count == 1
    assert lists["ORPHANED"].referenced_by == []


NXOS_CONFIG = """version 10.3(5)
hostname leaf1
feature bgp
ip prefix-list FABRIC_OUT seq 5 permit 10.1.0.0/16 le 24
ip prefix-list FABRIC_OUT seq 10 deny 0.0.0.0/0
route-map REDIST permit 10
  match ip address prefix-list FABRIC_OUT
  set metric 100
"""


def test_the_same_extractors_work_on_nxos():
    """Routing policy is spelled the same way on both platforms, which is why
    the extractors are shared rather than duplicated."""
    model, _ = nxos.parse(NXOS_CONFIG, platform="nxos")
    lists = {p.name: p for p in model.prefix_lists}
    assert lists["FABRIC_OUT"].entry_count == 2
    assert lists["FABRIC_OUT"].entries[0].le == "24"
    assert lists["FABRIC_OUT"].referenced_by == ["route-map REDIST"]
    assert model.route_maps[0].clauses[0].set == ["metric 100"]


def test_policy_now_counts_as_modelled_not_merely_recognised():
    """These lines used to be acknowledged-but-unmodelled, which is why a real
    change to them produced no diff in device.yaml."""
    _, doc = ios.parse(IOS_CONFIG, platform="iosxe")
    assert doc.coverage() > 0.5
    assert not [line for _, line in doc.unconsumed() if "prefix-list" in line]


DESCRIPTION_ONLY = """hostname R9
!
ip prefix-list TRANSIT-PREPEND description AS-Prepend transit routes
!
route-map EDGE-OUT permit 10
 match ip address prefix-list TRANSIT-PREPEND
!
"""


def test_a_prefix_list_with_only_a_description_is_still_modelled():
    """Found on an edge router in the estate. Consuming the description without recording the
    list made it indistinguishable from one that was never configured."""
    device, _ = ios.parse(DESCRIPTION_ONLY, platform="iosxe")
    lists = {pl.name: pl for pl in device.prefix_lists}

    assert "TRANSIT-PREPEND" in lists
    modelled = lists["TRANSIT-PREPEND"]
    assert modelled.description == "AS-Prepend transit routes"
    assert modelled.entries == []
    assert modelled.referenced_by == ["route-map EDGE-OUT"]
