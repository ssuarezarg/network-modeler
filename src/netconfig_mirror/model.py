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
    # ASA. `nameif` is the join key for the whole configuration - NAT pairs,
    # access-groups and crypto maps all refer to an interface by this name and
    # never by `GigabitEthernet0/0`. Without it nothing else cross-references.
    nameif: str | None = None
    security_level: str | None = None
    standby_ip: str | None = None
    # VTI. A route-based tunnel carries its whole VPN configuration here
    # rather than in a crypto map, so an interface that is not read for these
    # loses the tunnel entirely - and, because the block is consumed whole,
    # loses it while reporting the lines as modelled.
    tunnel_source: str | None = None
    tunnel_destination: str | None = None
    tunnel_mode: str | None = None
    tunnel_protection: str | None = None


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
    # ASA names the egress interface on every route, by nameif. It is not a
    # VRF and must not be written into that field: two default routes out of
    # two interfaces are the normal shape here, and reading them as two VRFs
    # would invent a segmentation the device does not have.
    interface: str | None = None
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
    # Prefix-lists applied straight to this neighbour, as written: "NAME in".
    # The common shape on an edge router carrying per-customer policy - no
    # route-map in between - and missing it made almost every prefix-list on
    # those routers look unreferenced.
    prefix_lists: list[str] = field(default_factory=list)
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
    description: str | None = None
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


# --- ASA ---------------------------------------------------------------
# Objects are the vocabulary the rest of an ASA configuration is written in:
# an access-list or a NAT rule names an object far more often than it names an
# address, so without these the policy reads as references to nothing.


@dataclass
class NetworkObject:
    name: str
    kind: str | None = None          # host | subnet | range | fqdn
    value: str | None = None
    description: str | None = None
    # Object NAT, configured inside the object rather than as a `nat` line.
    nat: str | None = None
    referenced_by: list[str] = field(default_factory=list)


@dataclass
class ObjectGroup:
    name: str
    kind: str | None = None          # network | service | protocol | icmp-type
    protocol: str | None = None      # `object-group service NAME tcp`
    description: str | None = None
    members: list[str] = field(default_factory=list)
    member_count: int = 0
    referenced_by: list[str] = field(default_factory=list)


@dataclass
class AccessGroup:
    """Where an access-list is actually applied. An ACL that exists but is in
    no access-group filters nothing, which is invisible by reading either one
    on its own."""

    access_list: str
    direction: str | None = None     # in | out | global
    interface: str | None = None


@dataclass
class NatRule:
    source_interface: str | None = None
    destination_interface: str | None = None
    kind: str | None = None          # static | dynamic
    section: str | None = None       # after-auto, twice-nat section
    rule: str = ""                   # the remainder, verbatim


@dataclass
class IkePolicy:
    version: str                     # ikev1 | ikev2
    priority: str
    authentication: str | None = None
    encryption: str | None = None
    integrity: str | None = None     # `hash` on ikev1, `integrity` on ikev2
    group: str | None = None
    prf: str | None = None
    lifetime: str | None = None


@dataclass
class IpsecProposal:
    name: str
    version: str                     # ikev1 transform-set | ikev2 proposal
    transforms: list[str] = field(default_factory=list)


@dataclass
class CryptoMapEntry:
    seq: str
    peers: list[str] = field(default_factory=list)
    match_address: str | None = None
    ikev1_transform_sets: list[str] = field(default_factory=list)
    ikev2_proposals: list[str] = field(default_factory=list)
    pfs: str | None = None
    lifetime: str | None = None


@dataclass
class CryptoMap:
    name: str
    interface: str | None = None
    entries: list[CryptoMapEntry] = field(default_factory=list)


@dataclass
class TunnelGroup:
    name: str                        # a peer address, for site-to-site
    type: str | None = None
    default_group_policy: str | None = None
    # Whether a key is configured, never the key. The value is a redaction
    # token by the time the parser sees it, and a token in the model would
    # change whenever the key is rotated - which is information worth having,
    # but it belongs in the diff of raw.cfg, not in a boolean's place.
    has_pre_shared_key: bool = False
    ikev2_local_authentication: str | None = None
    ikev2_remote_authentication: str | None = None
    # Crypto map entries whose peer is this tunnel-group. Computed, and the
    # reason this is modelled: a tunnel-group no crypto map points at is a peer
    # that was configured and never wired up, or one left behind by a
    # decommission.
    referenced_by: list[str] = field(default_factory=list)


@dataclass
class IpsecProfile:
    """Route-based VPN. Applied to a tunnel interface rather than matched by
    an ACL, so a profile and a crypto map are two different ways of building a
    tunnel and only one of them is visible from the access-lists."""

    name: str
    ikev1_transform_sets: list[str] = field(default_factory=list)
    ikev2_proposals: list[str] = field(default_factory=list)
    pfs: str | None = None
    lifetime: str | None = None
    referenced_by: list[str] = field(default_factory=list)


@dataclass
class Vpn:
    enabled_on: list[str] = field(default_factory=list)
    ike_policies: list[IkePolicy] = field(default_factory=list)
    ipsec_proposals: list[IpsecProposal] = field(default_factory=list)
    ipsec_profiles: list[IpsecProfile] = field(default_factory=list)
    crypto_maps: list[CryptoMap] = field(default_factory=list)
    tunnel_groups: list[TunnelGroup] = field(default_factory=list)


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
    # ASA. Absent on every other platform, and `_prune` drops them there.
    objects: list[NetworkObject] = field(default_factory=list)
    object_groups: list[ObjectGroup] = field(default_factory=list)
    access_groups: list[AccessGroup] = field(default_factory=list)
    nat: list[NatRule] = field(default_factory=list)
    vpn: Vpn | None = None
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
