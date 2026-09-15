"""IOS / IOS-XE parser: configuration text -> DeviceModel.

Covers the platforms that make up the estate today. NX-OS, IOS-XR and ASA share
enough syntax that several extractors here will transfer, but they get their own
modules rather than special cases bolted onto this one.

Every extractor either `consume`s a block (it produced model content) or
`acknowledge`s it (recognised, deliberately not modelled). Anything it does
neither to shows up in the coverage report as unrecognised, which is how the
next thing worth parsing gets chosen from evidence instead of guesswork.
"""
from __future__ import annotations

import re

from ..blocks import Block, ConfigDocument
from . import common
from ..model import (
    AccessList,
    Bgp,
    BgpNeighbor,
    Device,
    DeviceModel,
    Interface,
    Ospf,
    Services,
    StaticRoute,
    Vlan,
    Vrf,
)

# Global commands that are real configuration but carry nothing the model needs:
# service toggles, boot statements, cosmetic and platform defaults. Recognised so
# they do not pollute the "unrecognised" list, counted separately so they cannot
# inflate the coverage figure.
_ACKNOWLEDGED = re.compile(
    r"^(?:no\s+)?(?:"
    # Global toggles, boot and platform defaults.
    r"service\b|boot\b|version\b|platform\b|hostname\b|enable\b|upgrade\b"
    r"|archive\b|spanning-tree\b|errdisable\b|diagnostic\b|license\b|memory\b"
    r"|process\b|redundancy\b|subscriber\b|multilink\b|voice-card\b|vtp\b"
    r"|udld\b|power\b|system\b|clock\b|crypto\b|line\b|banner\b|alias\b"
    r"|privilege\b|parser\b|file\b|call-home\b|cdp\b|lldp\b|track\b|event\b"
    r"|control-plane\b|end\b|exit\b|port-channel\b|login\b|flow\b"
    # Seen on real IOS-XE 17 edge routers. DHCP pools are genuine configuration
    # and a reasonable thing to model later; recognised for now so they are not
    # reported as unknown.
    r"|ip\s+dhcp\b|security\b|exception\b|ipv6\b|vstack\b|ethernet\b"
    # ip-prefixed globals that are not addressing.
    r"|ip\s+(?:subnet-zero|source-route|classless|cef|domain[-\s]lookup|ssh"
    r"|forward-protocol|http|ftp|bootp|finger|tcp|icmp|routing|scp|tftp|tacacs"
    r"|bgp-community|community-list|as-path|sla)\b"
    # Policy constructs referenced by the model but not modelled themselves.
    r"|class-map\b|policy-map\b|table-map\b|object-group\b"
    # Management. The modelled parts (snmp-server community/user/host, ntp
    # server, logging host, aaa, username) are consumed before this runs; what
    # is left here is the remainder - snmp-server view/group/location, aaa
    # session-id, and so on.
    r"|snmp-server\b|snmp\b|logging\b|ntp\b|aaa\b|username\b"
    r"|tacacs-server\b|radius-server\b|tacacs\b|radius\b"
    # VRF and interface blocks are modelled; a stray unmatched variant here is
    # recognised rather than reported as unknown.
    r"|vrf\b|ip\s+vrf\b"
    r")",
    re.I,
)


def parse(config_text: str, *, platform: str | None = None,
          os_version: str | None = None) -> tuple[DeviceModel, ConfigDocument]:
    doc = ConfigDocument(config_text)
    model = DeviceModel()

    model.device = _device(doc, platform, os_version)
    model.vrfs = _vrfs(doc)
    model.interfaces = _interfaces(doc)
    model.vlans = _vlans(doc)
    model.static_routes = _static_routes(doc)
    model.bgp = _bgp(doc)
    model.ospf = _ospf(doc)
    model.access_lists = _access_lists(doc)
    model.prefix_lists = common.parse_prefix_lists(doc)
    model.route_maps = common.parse_route_maps(doc)
    common.link_references(model.prefix_lists, model.route_maps, model.bgp)
    model.services = _services(doc)

    _acknowledge_remainder(doc)
    return model, doc


def _device(doc: ConfigDocument, platform: str | None, os_version: str | None) -> Device:
    hostname = None
    for block in doc.find(r"hostname\s+"):
        hostname = block.header.split(None, 1)[1].strip()
        doc.consume(block)
    if os_version is None:
        for block in doc.find(r"version\s+\d"):
            os_version = block.header.split(None, 1)[1].strip()
    return Device(hostname=hostname, platform=platform, os_version=os_version)


def _vrfs(doc: ConfigDocument) -> list[Vrf]:
    vrfs = []
    # `vrf definition X` (newer) and `ip vrf X` (older) both appear in the estate.
    for block in doc.find(r"(?:vrf definition|ip vrf)\s+\S+"):
        name = block.header.split()[-1]
        vrf = Vrf(
            name=name,
            rd=block.first(r"rd\s+(\S+)"),
            description=block.first(r"description\s+(.+)"),
            import_targets=block.child_values(r"route-target import\s+(\S+)"),
            export_targets=block.child_values(r"route-target export\s+(\S+)"),
            address_families=block.child_values(r"address-family\s+(.+)"),
        )
        vrfs.append(vrf)
        doc.consume(block)
    return sorted(vrfs, key=lambda v: v.name)


def _interfaces(doc: ConfigDocument) -> list[Interface]:
    interfaces = []
    for block in doc.find(r"interface\s+\S+"):
        name = block.header.split(None, 1)[1].strip()
        interface = Interface(
            name=name,
            description=block.first(r"description\s+(.+)"),
            enabled=not block.has(r"shutdown$"),
            vrf=block.first(r"(?:vrf forwarding|ip vrf forwarding)\s+(\S+)"),
            ipv4=block.child_values(r"ip address\s+(.+)"),
            ipv6=block.child_values(r"ipv6 address\s+(.+)"),
            switchport_mode=block.first(r"switchport mode\s+(\S+)"),
            access_vlan=block.first(r"switchport access vlan\s+(\S+)"),
            trunk_vlans=block.first(r"switchport trunk allowed vlan\s+(.+)"),
            channel_group=block.first(r"channel-group\s+(\S+)"),
            mtu=block.first(r"(?:ip )?mtu\s+(\S+)"),
            hsrp_groups=block.child_values(r"standby\s+(\d+)\s+ip"),
            service_policies=block.child_values(r"service-policy\s+(.+)"),
            helper_addresses=block.child_values(r"ip helper-address\s+(\S+)"),
        )
        interfaces.append(interface)
        doc.consume(block)
    return sorted(interfaces, key=lambda i: _interface_sort_key(i.name))


def _interface_sort_key(name: str):
    """Sort Gi0/2 before Gi0/10 -- string order would not, and a reordering diff
    on an unchanged device is exactly the noise this project avoids."""
    parts = re.split(r"(\d+)", name)
    return [int(p) if p.isdigit() else p.lower() for p in parts]


def _vlans(doc: ConfigDocument) -> list[Vlan]:
    vlans = []
    for block in doc.find(r"vlan\s+\d"):
        ids = block.header.split(None, 1)[1].strip()
        # `vlan 10,20,30` and `vlan 10-12` are both legal; only a single id
        # carries a name, so ranges are recorded without one.
        if re.fullmatch(r"\d+", ids):
            vlans.append(Vlan(id=ids, name=block.first(r"name\s+(.+)")))
        else:
            for part in ids.split(","):
                vlans.append(Vlan(id=part.strip()))
        doc.consume(block)
    return sorted(vlans, key=lambda v: (len(v.id), v.id))


def _static_routes(doc: ConfigDocument) -> list[StaticRoute]:
    routes = []
    pattern = re.compile(
        r"ip route\s+(?:vrf\s+(?P<vrf>\S+)\s+)?(?P<prefix>\S+\s+\S+)\s+(?P<rest>.+)$", re.I)
    for block in doc.find(r"ip route\s+"):
        match = pattern.match(block.header)
        if not match:
            continue
        rest = match.group("rest").split()
        distance = next((t for t in rest[1:] if t.isdigit()), None)
        track = None
        if "track" in rest:
            track = rest[rest.index("track") + 1] if rest.index("track") + 1 < len(rest) else None
        routes.append(StaticRoute(
            prefix=match.group("prefix"),
            next_hop=rest[0] if rest else None,
            vrf=match.group("vrf"),
            distance=distance,
            track=track,
        ))
        doc.consume(block)
    return sorted(routes, key=lambda r: (r.vrf or "", r.prefix))


def _bgp(doc: ConfigDocument) -> Bgp | None:
    blocks = doc.find(r"router bgp\s+\d")
    if not blocks:
        return None
    block = blocks[0]
    bgp = Bgp(
        asn=block.header.split()[-1],
        router_id=block.first(r"bgp router-id\s+(\S+)"),
        address_families=block.child_values(r"address-family\s+(.+)"),
        redistribute=block.child_values(r"redistribute\s+(.+)"),
    )

    neighbors: dict[str, BgpNeighbor] = {}
    current_vrf: str | None = None
    for child in block.children:
        stripped = child.strip()
        af = re.match(r"address-family\s+\S+(?:\s+vrf\s+(\S+))?", stripped)
        if af:
            current_vrf = af.group(1)
            continue
        if stripped.startswith("exit-address-family"):
            current_vrf = None
            continue
        match = re.match(r"neighbor\s+(\S+)\s+(.+)$", stripped)
        if not match:
            continue
        peer, rest = match.group(1), match.group(2)
        key = f"{current_vrf or ''}|{peer}"
        neighbor = neighbors.setdefault(key, BgpNeighbor(peer=peer, vrf=current_vrf))
        if remote := re.match(r"remote-as\s+(\S+)", rest):
            neighbor.remote_as = remote.group(1)
        elif desc := re.match(r"description\s+(.+)", rest):
            neighbor.description = desc.group(1)
        elif source := re.match(r"update-source\s+(\S+)", rest):
            neighbor.update_source = source.group(1)
        elif rmap := re.match(r"route-map\s+(.+)", rest):
            neighbor.route_maps.append(rmap.group(1))
        elif plist := re.match(r"prefix-list\s+(\S+\s+\S+)", rest):
            neighbor.prefix_lists.append(plist.group(1))
        elif dlist := re.match(r"distribute-list\s+prefix\s+(\S+\s+\S+)", rest):
            neighbor.prefix_lists.append(dlist.group(1))
        elif rest.startswith("password"):
            # Presence only. The value is already a redaction token here.
            neighbor.authenticated = True

    bgp.neighbors = sorted(neighbors.values(), key=lambda n: (n.vrf or "", n.peer))
    doc.consume(block)
    return bgp


def _ospf(doc: ConfigDocument) -> list[Ospf]:
    processes = []
    for block in doc.find(r"router ospf\s+\d"):
        parts = block.header.split()
        vrf = parts[parts.index("vrf") + 1] if "vrf" in parts else None
        processes.append(Ospf(
            process_id=parts[2],
            router_id=block.first(r"router-id\s+(\S+)"),
            vrf=vrf,
            networks=block.child_values(r"network\s+(.+)"),
            passive_interfaces=block.child_values(r"passive-interface\s+(\S+)"),
            redistribute=block.child_values(r"redistribute\s+(.+)"),
        ))
        doc.consume(block)
    return sorted(processes, key=lambda o: o.process_id)


def _access_lists(doc: ConfigDocument) -> list[AccessList]:
    acls: dict[str, AccessList] = {}

    for block in doc.find(r"ip access-list\s+"):
        parts = block.header.split()
        acl = AccessList(name=parts[-1], type=parts[2] if len(parts) > 3 else None)
        acl.entries = [child.strip() for child in block.children]
        acl.entry_count = len(acl.entries)
        acls[acl.name] = acl
        doc.consume(block)

    # Numbered ACLs: one line per entry, no block structure.
    for block in doc.find(r"access-list\s+\d"):
        parts = block.header.split()
        name = parts[1]
        acl = acls.setdefault(name, AccessList(name=name, type="numbered"))
        acl.entries.append(" ".join(parts[2:]))
        acl.entry_count = len(acl.entries)
        doc.consume(block)

    return sorted(acls.values(), key=lambda a: (len(a.name), a.name))


def _services(doc: ConfigDocument) -> Services:
    services = Services()

    def collect(pattern: str, sink: list[str], group: int = 1) -> None:
        compiled = re.compile(pattern, re.I)
        for block in doc.blocks:
            match = compiled.match(block.header)
            if match:
                sink.append(match.group(group))
                doc.consume(block)

    collect(r"ntp server\s+(?:vrf\s+\S+\s+)?(\S+)", services.ntp_servers)
    collect(r"ip name-server\s+(?:vrf\s+\S+\s+)?(.+)", services.name_servers)
    collect(r"logging host\s+(?:vrf\s+\S+\s+)?(\S+)", services.logging_hosts)
    collect(r"snmp-server host\s+(\S+)", services.snmp_traps_hosts)
    collect(r"snmp-server user\s+(\S+)", services.snmp_v3_users)
    collect(r"aaa (?:authentication|authorization|accounting|group)\s+(.+)", services.aaa)
    collect(r"username\s+(\S+)", services.local_users)

    for block in doc.find(r"ip domain[-\s]name\s+"):
        services.domain_name = block.header.split()[-1]
        doc.consume(block)

    for block in doc.find(r"snmp-server community\s+"):
        services.snmp_communities += 1
        doc.consume(block)

    services.ntp_servers = sorted(set(services.ntp_servers))
    services.logging_hosts = sorted(set(services.logging_hosts))
    services.snmp_v3_users = sorted(set(services.snmp_v3_users))
    services.local_users = sorted(set(services.local_users))
    services.snmp_traps_hosts = sorted(set(services.snmp_traps_hosts))
    return services


def _acknowledge_remainder(doc: ConfigDocument) -> None:
    for block in doc.blocks:
        if _ACKNOWLEDGED.match(block.header):
            doc.acknowledge(block)
