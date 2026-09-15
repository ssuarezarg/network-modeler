"""The L1 device model - the structured representation that gets committed.

Plain dataclasses rather than pydantic: this has to run in the viewer
environment, and every dependency is something someone has to approve there.
PyYAML is already present; nothing else is needed.

Rendering rules, both of which exist to keep diffs meaningful:
  * Empty values are omitted. A device with no BGP should not carry an empty
    `bgp:` key that looks like a finding.
  * Key order is fixed by declaration order, and lists are sorted by a stable
    natural key. The same input must always produce byte-identical output.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields, is_dataclass

SCHEMA_VERSION = 1


@dataclass
class Interface:
    name: str
    description: str | None = None
    enabled: bool = True
    vrf: str | None = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    switchport_mode: str | None = None
    access_vlan: str | None = None
    trunk_vlans: str | None = None
    channel_group: str | None = None
    mtu: str | None = None
    hsrp_groups: list[str] = field(default_factory=list)
    service_policies: list[str] = field(default_factory=list)
    helper_addresses: list[str] = field(default_factory=list)


@dataclass
class Vrf:
    name: str
    rd: str | None = None
    vni: str | None = None
    description: str | None = None
    import_targets: list[str] = field(default_factory=list)
    export_targets: list[str] = field(default_factory=list)
    address_families: list[str] = field(default_factory=list)


@dataclass
class StaticRoute:
    prefix: str
    next_hop: str | None = None
    vrf: str | None = None
    distance: str | None = None
    track: str | None = None


@dataclass
class BgpNeighbor:
    peer: str
    remote_as: str | None = None
    description: str | None = None
    vrf: str | None = None
    update_source: str | None = None
    route_maps: list[str] = field(default_factory=list)
    # Whether authentication is configured - never the value, which redaction
    # has already replaced by the time the parser sees it.
    authenticated: bool = False


@dataclass
class Bgp:
    asn: str
    router_id: str | None = None
    neighbors: list[BgpNeighbor] = field(default_factory=list)
    address_families: list[str] = field(default_factory=list)
    redistribute: list[str] = field(default_factory=list)


@dataclass
class Ospf:
    process_id: str
    router_id: str | None = None
    vrf: str | None = None
    networks: list[str] = field(default_factory=list)
    passive_interfaces: list[str] = field(default_factory=list)
    redistribute: list[str] = field(default_factory=list)


@dataclass
class AccessList:
    name: str
    type: str | None = None
    entry_count: int = 0
    entries: list[str] = field(default_factory=list)


@dataclass
class PrefixListEntry:
    action: str                  # permit | deny
    prefix: str
    seq: str | None = None
    ge: str | None = None
    le: str | None = None


@dataclass
class PrefixList:
    name: str
    entry_count: int = 0
    entries: list[PrefixListEntry] = field(default_factory=list)
    # Route-maps that match this list. Computed rather than parsed, and the
    # reason this is modelled at all: a prefix-list nothing references announces
    # nothing. An empty list here means the entries are inert - staged, or left
    # behind by a change that was never finished.
    referenced_by: list[str] = field(default_factory=list)


@dataclass
class RouteMapClause:
    seq: str
    action: str                  # permit | deny
    match: list[str] = field(default_factory=list)
    set: list[str] = field(default_factory=list)


@dataclass
class RouteMap:
    name: str
    clauses: list[RouteMapClause] = field(default_factory=list)
    # Prefix-lists this route-map matches on, flattened for readability.
    prefix_lists: list[str] = field(default_factory=list)


@dataclass
class Vlan:
    id: str
    name: str | None = None
    # NX-OS: the VXLAN VNI this VLAN maps to.
    vn_segment: str | None = None


@dataclass
class Services:
    ntp_servers: list[str] = field(default_factory=list)
    name_servers: list[str] = field(default_factory=list)
    logging_hosts: list[str] = field(default_factory=list)
    snmp_communities: int = 0
    snmp_v3_users: list[str] = field(default_factory=list)
    snmp_traps_hosts: list[str] = field(default_factory=list)
    aaa: list[str] = field(default_factory=list)
    local_users: list[str] = field(default_factory=list)
    domain_name: str | None = None


@dataclass
class NveInterface:
    """NX-OS VXLAN tunnel endpoint. The VNI list is the fabric's actual reach -
    which segments this switch participates in - and is the single most useful
    thing to diff on an EVPN leaf."""

    name: str
    source_interface: str | None = None
    host_reachability: str | None = None
    enabled: bool = True
    vnis: list[str] = field(default_factory=list)


@dataclass
class Device:
    hostname: str | None = None
    platform: str | None = None
    os_version: str | None = None


@dataclass
class DeviceModel:
    schema_version: int = SCHEMA_VERSION
    device: Device = field(default_factory=Device)
    vrfs: list[Vrf] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    static_routes: list[StaticRoute] = field(default_factory=list)
    bgp: Bgp | None = None
    ospf: list[Ospf] = field(default_factory=list)
    # NX-OS: enabled feature set. The closest thing the platform has to a
    # declaration of what the switch is for, and a feature appearing or
    # disappearing is a significant change.
    features: list[str] = field(default_factory=list)
    nve: NveInterface | None = None
    access_lists: list[AccessList] = field(default_factory=list)
    prefix_lists: list[PrefixList] = field(default_factory=list)
    route_maps: list[RouteMap] = field(default_factory=list)
    services: Services = field(default_factory=Services)

    def to_dict(self) -> dict:
        return _prune(asdict(self))


def _prune(value):
    """Drop empty values, recursively, preserving declaration order.

    `False` and `0` are kept: `enabled: false` and `snmp_communities: 0` are
    statements about the device, not absences.
    """
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            pruned = _prune(item)
            if pruned is None or pruned == [] or pruned == {}:
                continue
            out[key] = pruned
        return out
    if isinstance(value, list):
        return [_prune(item) for item in value]
    return value


def field_order(cls) -> list[str]:
    assert is_dataclass(cls)
    return [f.name for f in fields(cls)]
