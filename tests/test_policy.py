"""Routing policy: prefix-lists and route-maps, on both platforms.

Modelled because it is what actually changes. The first real diff the mirror
produced was a hundred new prefix-list entries across six devices — and the
model saw none of it.
"""
from netconfig_mirror.parsers import ios, nxos

IOS_CONFIG = """hostname R1
!
ip prefix-list LUMEN_OUT seq 5 permit 10.1.10.100/32
ip prefix-list LUMEN_OUT seq 10 permit 10.111.0.0/16
ip prefix-list LUMEN_OUT seq 15 permit 136.228.182.0/24 le 32
ip prefix-list LUMEN_OUT seq 200 deny 0.0.0.0/0 le 32
!
ip prefix-list ORPHANED seq 5 permit 192.168.0.0/16
!
ip prefix-list WITH_GE seq 5 permit 10.0.0.0/8 ge 24 le 30
!
route-map TO-LUMEN permit 10
 match ip address prefix-list LUMEN_OUT
 set local-preference 200
!
route-map TO-LUMEN deny 20
!
route-map OTHER permit 5
 match ip address prefix-list LUMEN_OUT WITH_GE
!
router bgp 65001
 neighbor 10.0.0.1 remote-as 65002
 neighbor 10.0.0.1 route-map TO-LUMEN out
"""


def _ios():
    model, _ = ios.parse(IOS_CONFIG, platform="iosxe")
    return model


def test_prefix_list_entries_are_parsed():
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["LUMEN_OUT"].entry_count == 4
    first = lists["LUMEN_OUT"].entries[0]
    assert (first.action, first.prefix, first.seq) == ("permit", "10.1.10.100/32", "5")


def test_deny_entries_are_kept():
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["LUMEN_OUT"].entries[-1].action == "deny"


def test_ge_and_le_are_captured():
    """A prefix with le 32 matches every more-specific route inside it. Dropping
    that qualifier would make two very different policies look identical."""
    lists = {p.name: p for p in _ios().prefix_lists}
    entry = lists["WITH_GE"].entries[0]
    assert (entry.ge, entry.le) == ("24", "30")
    assert lists["LUMEN_OUT"].entries[2].le == "32"


def test_entries_are_ordered_by_sequence_not_by_prefix():
    """Sequence order is the order the device evaluates them in. Sorting by
    prefix would look tidier and misrepresent the policy."""
    seqs = [e.seq for e in {p.name: p for p in _ios().prefix_lists}["LUMEN_OUT"].entries]
    assert seqs == ["5", "10", "15", "200"]


def test_route_map_clauses_are_grouped_by_name():
    """IOS writes each clause as its own top-level block, so one route-map
    arrives as several blocks sharing a name."""
    maps = {m.name: m for m in _ios().route_maps}
    assert len(maps["TO-LUMEN"].clauses) == 2
    assert [c.seq for c in maps["TO-LUMEN"].clauses] == ["10", "20"]
    assert maps["TO-LUMEN"].clauses[1].action == "deny"


def test_match_and_set_lines_are_kept():
    maps = {m.name: m for m in _ios().route_maps}
    clause = maps["TO-LUMEN"].clauses[0]
    assert clause.match == ["ip address prefix-list LUMEN_OUT"]
    assert clause.set == ["local-preference 200"]


def test_one_match_line_can_name_several_prefix_lists():
    maps = {m.name: m for m in _ios().route_maps}
    assert maps["OTHER"].prefix_lists == ["LUMEN_OUT", "WITH_GE"]


def test_a_referenced_prefix_list_records_who_uses_it():
    lists = {p.name: p for p in _ios().prefix_lists}
    assert lists["LUMEN_OUT"].referenced_by == ["OTHER", "TO-LUMEN"]


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
    assert lists["FABRIC_OUT"].referenced_by == ["REDIST"]
    assert model.route_maps[0].clauses[0].set == ["metric 100"]


def test_policy_now_counts_as_modelled_not_merely_recognised():
    """These lines used to be acknowledged-but-unmodelled, which is why a real
    change to them produced no diff in device.yaml."""
    _, doc = ios.parse(IOS_CONFIG, platform="iosxe")
    assert doc.coverage() > 0.5
    assert not [line for _, line in doc.unconsumed() if "prefix-list" in line]
