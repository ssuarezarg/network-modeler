"""Extractors shared by the IOS and NX-OS parsers.

Routing policy is spelled the same way on both platforms, and it is the part of
these configurations that actually changes: the first real diff the mirror
produced was a hundred new prefix-list entries across six devices, none of which
the model saw. These extractors are that gap closed.

The linkage matters as much as the contents. A prefix-list is inert on its own —
a route-map has to match it, and a neighbour has to apply that route-map, before
a single prefix is announced. `link_references` walks the middle of that chain,
which is what makes "this list is not referenced by anything" a visible fact
rather than something you notice months later.
"""
from __future__ import annotations

import re

from ..blocks import ConfigDocument
from ..model import PrefixList, PrefixListEntry, RouteMap, RouteMapClause

_PREFIX_LIST = re.compile(
    r"^ip(?:v6)?\s+prefix-list\s+(?P<name>\S+)\s+"
    r"(?:seq\s+(?P<seq>\d+)\s+)?"
    r"(?P<action>permit|deny)\s+"
    r"(?P<prefix>\S+)"
    r"(?:\s+ge\s+(?P<ge>\d+))?"
    r"(?:\s+le\s+(?P<le>\d+))?",
    re.I,
)

_PREFIX_LIST_DESCRIPTION = re.compile(
    r"^ip(?:v6)?\s+prefix-list\s+(?P<name>\S+)\s+description\s+(?P<text>.+)$", re.I)

_ROUTE_MAP = re.compile(
    r"^route-map\s+(?P<name>\S+)\s+(?P<action>permit|deny)\s+(?P<seq>\d+)", re.I)

# `match ip address prefix-list A B C` names several lists on one line.
_MATCH_PREFIX_LIST = re.compile(
    r"^match\s+ip(?:v6)?\s+address\s+prefix-list\s+(?P<names>.+)$", re.I)


def parse_prefix_lists(doc: ConfigDocument) -> list[PrefixList]:
    lists: dict[str, PrefixList] = {}

    for block in doc.blocks:
        match = _PREFIX_LIST.match(block.header)
        if match:
            entry = PrefixListEntry(
                action=match.group("action").lower(),
                prefix=match.group("prefix"),
                seq=match.group("seq"),
                ge=match.group("ge"),
                le=match.group("le"),
            )
            prefix_list = lists.setdefault(match.group("name"),
                                           PrefixList(name=match.group("name")))
            prefix_list.entries.append(entry)
            doc.consume(block)
        elif described := _PREFIX_LIST_DESCRIPTION.match(block.header):
            # A description carries no policy, but it does prove the list was
            # declared. Recording it separates "this name does not exist" from
            # "this list exists and is empty" - the same effect on traffic,
            # different causes and different fixes.
            name = described.group("name")
            prefix_list = lists.setdefault(name, PrefixList(name=name))
            prefix_list.description = described.group("text").strip()
            doc.consume(block)

    for prefix_list in lists.values():
        # Ordered by sequence number, because that is the order the device
        # evaluates them in - not sorted by prefix, which would look tidier and
        # misrepresent the policy.
        prefix_list.entries.sort(key=lambda e: int(e.seq) if e.seq else 0)
        prefix_list.entry_count = len(prefix_list.entries)

    return sorted(lists.values(), key=lambda p: p.name)


def parse_route_maps(doc: ConfigDocument) -> list[RouteMap]:
    maps: dict[str, RouteMap] = {}

    for block in doc.blocks:
        match = _ROUTE_MAP.match(block.header)
        if not match:
            continue

        clause = RouteMapClause(seq=match.group("seq"),
                                action=match.group("action").lower())
        for child in block.children:
            stripped = child.strip()
            if stripped.startswith("match "):
                clause.match.append(stripped[len("match "):])
            elif stripped.startswith("set "):
                clause.set.append(stripped[len("set "):])

        # IOS writes each clause as its own top-level block, so one route-map
        # arrives as several blocks sharing a name.
        route_map = maps.setdefault(match.group("name"), RouteMap(name=match.group("name")))
        route_map.clauses.append(clause)
        doc.consume(block)

    for route_map in maps.values():
        route_map.clauses.sort(key=lambda c: int(c.seq))
        names: list[str] = []
        for clause in route_map.clauses:
            for match_line in clause.match:
                found = _MATCH_PREFIX_LIST.match(f"match {match_line}")
                if found:
                    names.extend(found.group("names").split())
        route_map.prefix_lists = sorted(set(names))

    return sorted(maps.values(), key=lambda m: m.name)


def link_references(prefix_lists: list[PrefixList], route_maps: list[RouteMap],
                    bgp=None) -> None:
    """Record what references each prefix-list.

    Cheap to compute and the reason prefix-lists are worth modelling: a list
    nothing references announces nothing, however many entries it holds.

    **Both kinds of reference count.** Route-maps are the obvious one; applying
    a prefix-list straight to a BGP neighbour is the other, and it is the usual
    shape on an edge router carrying per-customer policy. Counting only
    route-maps reported 1007 of roughly 1100 prefix-lists as inert across this
    estate - which was the tool being wrong, not the network.
    """
    users: dict[str, list[str]] = {}

    for route_map in route_maps:
        for name in route_map.prefix_lists:
            users.setdefault(name, []).append(f"route-map {route_map.name}")

    if bgp is not None:
        for neighbor in bgp.neighbors:
            for applied in neighbor.prefix_lists:
                # Stored as written - "NAME in" - so the direction survives for
                # a reader. Only the name identifies the list.
                name = applied.split()[0]
                users.setdefault(name, []).append(f"neighbor {neighbor.peer}")

    for prefix_list in prefix_lists:
        prefix_list.referenced_by = sorted(set(users.get(prefix_list.name, [])))
