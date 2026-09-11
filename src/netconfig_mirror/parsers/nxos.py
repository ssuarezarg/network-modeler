"""NX-OS parser: configuration text -> DeviceModel.

Written against real Nexus 9300v captures. NX-OS looks like IOS at a glance and
then differs in ways that quietly produce a wrong model rather than an error:

* **BGP neighbours are nested blocks.** IOS repeats `neighbor X <setting>` on
  flat lines; NX-OS opens `neighbor X` and indents its settings underneath, with
  address-families nested a level deeper again. A flat parser finds no
  neighbours at all and reports a BGP process with none.
* **`vrf member`, not `vrf forwarding`**, on interfaces.
* **Static routes live inside `vrf context`**, not as `ip route vrf X` at the
  top level.
* **`feature X`** has no IOS equivalent. It is the closest thing the platform
  has to a statement of what the switch is for, and a feature appearing or
  disappearing is a significant change worth seeing in a diff.
* **VXLAN**: `interface nve1` and the VLAN-to-VNI mapping are the fabric's
  actual reach. On an EVPN leaf they are the most useful thing to diff.
"""
from __future__ import annotations

import re

from ..blocks import Block, ConfigDocument
from ..model import (
    AccessList,
    Bgp,
    BgpNeighbor,
    Device,
    DeviceModel,
    Interface,
    NveInterface,
    Ospf,
    Services,
    StaticRoute,
    Vlan,
    Vrf,
)

_ACKNOWLEDGED = re.compile(
    r"^(?:no\s+)?(?:"
    r"version\b|boot\b|hostname\b|vdc\b|cfs\b|copp\b|rmon\b|system\b|clock\b"
    r"|line\b|banner\b|username\b|role\b|password\b|ssh\b|telnet\b|ntp\b"
    r"|logging\b|snmp-server\b|callhome\b|nxapi\b|telemetry\b|hardware\b"
    r"|ip\s+domain-lookup\b|ip\s+domain-name\b|ip\s+name-server\b|ip\s+pim\b"
    r"|ip\s+dhcp\b|ipv6\s+dhcp\b"
    r"|ipv6\b|ip\s+igmp\b|ip\s+tftp\b|ip\s+http\b|service\b|event\b|scheduler\b"
    r"|fabric\b|nv\s+overlay\b|evpn\b|route-map\b|ip\s+prefix-list\b"
    r"|ip\s+community-list\b|ip\s+as-path\b|class-map\b|policy-map\b|table-map\b"
    r"|control-plane\b|spanning-tree\b|port-channel\b|errdisable\b|lacp\b"
    r"|vpc\b|track\b|object-group\b|key\b|aaa\b|tacacs\b|radius\b|license\b"
    r"|install\b|end\b|exit\b|configure\b|slot\b|powerredundancymode\b"
    r")",
    re.I,
)


def parse(config_text: str, *, platform: str | None = None,
          os_version: str | None = None) -> tuple[DeviceModel, ConfigDocument]:
    doc = ConfigDocument(config_text)
    model = DeviceModel()

    model.device = _device(doc, platform, os_version)
    model.features = _features(doc)
    model.vlans = _vlans(doc)
    model.vrfs, vrf_routes = _vrfs(doc)
    model.interfaces = _interfaces(doc)
    model.nve = _nve(doc)
    model.static_routes = _static_routes(doc) + vrf_routes
    model.static_routes.sort(key=lambda r: (r.vrf or "", r.prefix))
    model.bgp = _bgp(doc)
    model.ospf = _ospf(doc)
    model.access_lists = _access_lists(doc)
    model.services = _services(doc)

    for block in doc.blocks:
        if _ACKNOWLEDGED.match(block.header):
            doc.acknowledge(block)

    return model, doc


def _subblocks(children: list[str]) -> list[tuple[str, list[str]]]:
    """Split a block's children into nested sub-blocks by indentation.

    Needed because NX-OS nests: `router bgp` holds `neighbor X` blocks, which in
    turn hold `address-family` blocks. Treating the children as one flat list -
    which is enough for IOS - loses that structure entirely.
    """
    meaningful = [line for line in children if line.strip()]
    if not meaningful:
        return []

    base = min(len(line) - len(line.lstrip()) for line in meaningful)
    out: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None

    for line in meaningful:
        indent = len(line) - len(line.lstrip())
        if indent <= base:
            current = (line.strip(), [])
            out.append(current)
        elif current is not None:
            current[1].append(line)

    return out


def _device(doc: ConfigDocument, platform: str | None, os_version: str | None) -> Device:
    hostname = None
    for block in doc.find(r"hostname\s+"):
        hostname = block.header.split(None, 1)[1].strip()
        doc.consume(block)
    if os_version is None:
        for block in doc.find(r"version\s+\d"):
            # `version 10.6(1) Bios:version` - take the NX-OS version only.
            match = re.match(r"version\s+(\S+)", block.header)
            if match:
                os_version = match.group(1)
    return Device(hostname=hostname, platform=platform, os_version=os_version)


def _features(doc: ConfigDocument) -> list[str]:
    features = []
    for block in doc.find(r"feature\s+\S+"):
        features.append(block.header.split(None, 1)[1].strip())
        doc.consume(block)
    # `nv overlay evpn` enables VXLAN EVPN but is not spelled as a feature.
    for block in doc.find(r"nv overlay evpn"):
        features.append("nv overlay evpn")
        doc.consume(block)
    return sorted(set(features))


def _vlans(doc: ConfigDocument) -> list[Vlan]:
    vlans = []
    for block in doc.find(r"vlan\s+\d"):
        ids = block.header.split(None, 1)[1].strip()
        if re.fullmatch(r"\d+", ids):
            vlans.append(Vlan(
                id=ids,
                name=block.first(r"name\s+(.+)"),
                vn_segment=block.first(r"vn-segment\s+(\S+)"),
            ))
        else:
            for part in re.split(r"[,]", ids):
                part = part.strip()
                if part:
                    vlans.append(Vlan(id=part))
        doc.consume(block)
    return sorted(vlans, key=lambda v: (len(v.id), v.id))


def _vrfs(doc: ConfigDocument) -> tuple[list[Vrf], list[StaticRoute]]:
    vrfs: list[Vrf] = []
    routes: list[StaticRoute] = []

    for block in doc.find(r"vrf context\s+\S+"):
        name = block.header.split()[-1]
        vrf = Vrf(
            name=name,
            rd=block.first(r"rd\s+(\S+)"),
            vni=block.first(r"vni\s+(\S+)"),
            description=block.first(r"description\s+(.+)"),
            address_families=block.child_values(r"address-family\s+(.+)"),
            import_targets=block.child_values(r"route-target import\s+(.+)"),
            export_targets=block.child_values(r"route-target export\s+(.+)"),
        )
        vrfs.append(vrf)

        # NX-OS puts a VRF's static routes inside its context block, where the
        # IOS spelling `ip route vrf X ...` would never find them.
        for child in block.children:
            route = _parse_route(child.strip(), vrf=name)
            if route:
                routes.append(route)

        doc.consume(block)

    return sorted(vrfs, key=lambda v: v.name), routes


_ROUTE = re.compile(r"^ip route\s+(?P<prefix>\S+)\s+(?P<rest>.+)$", re.I)


def _parse_route(line: str, vrf: str | None = None) -> StaticRoute | None:
    match = _ROUTE.match(line)
    if not match:
        return None
    rest = match.group("rest").split()
    distance = next((token for token in rest[1:] if token.isdigit()), None)
    return StaticRoute(
        prefix=match.group("prefix"),   # NX-OS uses CIDR, not prefix + mask
        next_hop=rest[0] if rest else None,
        vrf=vrf,
        distance=distance,
    )


def _static_routes(doc: ConfigDocument) -> list[StaticRoute]:
    routes = []
    for block in doc.find(r"ip route\s+"):
        route = _parse_route(block.header)
        if route:
            routes.append(route)
            doc.consume(block)
    return routes


def _interfaces(doc: ConfigDocument) -> list[Interface]:
    interfaces = []
    for block in doc.find(r"interface\s+\S+"):
        name = block.header.split(None, 1)[1].strip()
        if name.lower().startswith("nve"):
            continue  # handled by _nve
        interfaces.append(Interface(
            name=name,
            description=block.first(r"description\s+(.+)"),
            enabled=not block.has(r"shutdown$"),
            vrf=block.first(r"vrf member\s+(\S+)"),
            ipv4=block.child_values(r"ip address\s+(.+)"),
            ipv6=block.child_values(r"ipv6 address\s+(.+)"),
            switchport_mode=block.first(r"switchport mode\s+(\S+)"),
            access_vlan=block.first(r"switchport access vlan\s+(\S+)"),
            trunk_vlans=block.first(r"switchport trunk allowed vlan\s+(.+)"),
            channel_group=block.first(r"channel-group\s+(\S+)"),
            mtu=block.first(r"mtu\s+(\S+)"),
            hsrp_groups=block.child_values(r"hsrp\s+(\d+)"),
            service_policies=block.child_values(r"service-policy\s+(.+)"),
            helper_addresses=block.child_values(r"ip dhcp relay address\s+(\S+)"),
        ))
        doc.consume(block)
    return sorted(interfaces, key=lambda i: _interface_sort_key(i.name))


def _interface_sort_key(name: str):
    parts = re.split(r"(\d+)", name)
    return [int(p) if p.isdigit() else p.lower() for p in parts]


def _nve(doc: ConfigDocument) -> NveInterface | None:
    blocks = doc.find(r"interface nve\d")
    if not blocks:
        return None
    block = blocks[0]
    nve = NveInterface(
        name=block.header.split(None, 1)[1].strip(),
        source_interface=block.first(r"source-interface\s+(\S+)"),
        host_reachability=block.first(r"host-reachability protocol\s+(\S+)"),
        enabled=not block.has(r"shutdown$"),
        vnis=[header.split()[2] for header, _ in _subblocks(block.children)
              if re.match(r"member vni \d", header)],
    )
    doc.consume(block)
    return nve


def _bgp(doc: ConfigDocument) -> Bgp | None:
    blocks = doc.find(r"router bgp\s+\S+")
    if not blocks:
        return None
    block = blocks[0]
    bgp = Bgp(asn=block.header.split()[-1])
    neighbors: list[BgpNeighbor] = []

    for header, children in _subblocks(block.children):
        if match := re.match(r"router-id\s+(\S+)", header):
            bgp.router_id = match.group(1)
        elif match := re.match(r"address-family\s+(.+)", header):
            bgp.address_families.append(match.group(1))
            bgp.redistribute += [
                sub for sub, _ in _subblocks(children) if sub.startswith("redistribute")]
        elif match := re.match(r"vrf\s+(\S+)", header):
            neighbors += _bgp_neighbors(children, vrf=match.group(1))
            bgp.address_families += [
                f"{sub} (vrf {match.group(1)})" for sub, _ in _subblocks(children)
                if sub.startswith("address-family")]
        elif header.startswith("neighbor "):
            neighbors.append(_bgp_neighbor(header, children))

    bgp.neighbors = sorted(neighbors, key=lambda n: (n.vrf or "", n.peer))
    doc.consume(block)
    return bgp


def _bgp_neighbors(children: list[str], *, vrf: str | None) -> list[BgpNeighbor]:
    return [_bgp_neighbor(header, sub, vrf=vrf)
            for header, sub in _subblocks(children) if header.startswith("neighbor ")]


def _bgp_neighbor(header: str, children: list[str], *,
                  vrf: str | None = None) -> BgpNeighbor:
    neighbor = BgpNeighbor(peer=header.split()[1], vrf=vrf)
    for line in children:
        stripped = line.strip()
        if match := re.match(r"remote-as\s+(\S+)", stripped):
            neighbor.remote_as = match.group(1)
        elif match := re.match(r"description\s+(.+)", stripped):
            neighbor.description = match.group(1)
        elif match := re.match(r"update-source\s+(\S+)", stripped):
            neighbor.update_source = match.group(1)
        elif match := re.match(r"route-map\s+(.+)", stripped):
            neighbor.route_maps.append(match.group(1))
        elif stripped.startswith("password"):
            neighbor.authenticated = True
    return neighbor


def _ospf(doc: ConfigDocument) -> list[Ospf]:
    processes = []
    for block in doc.find(r"router ospf\s+\S+"):
        processes.append(Ospf(
            process_id=block.header.split()[-1],
            router_id=block.first(r"router-id\s+(\S+)"),
            passive_interfaces=block.child_values(r"passive-interface\s+(\S+)"),
            redistribute=block.child_values(r"redistribute\s+(.+)"),
        ))
        doc.consume(block)
    return sorted(processes, key=lambda o: o.process_id)


def _access_lists(doc: ConfigDocument) -> list[AccessList]:
    acls = []
    for block in doc.find(r"ip access-list\s+"):
        acl = AccessList(name=block.header.split()[-1], type="ip")
        acl.entries = [child.strip() for child in block.children]
        acl.entry_count = len(acl.entries)
        acls.append(acl)
        doc.consume(block)
    return sorted(acls, key=lambda a: (len(a.name), a.name))


def _services(doc: ConfigDocument) -> Services:
    services = Services()

    def collect(pattern: str, sink: list[str]) -> None:
        compiled = re.compile(pattern, re.I)
        for block in doc.blocks:
            match = compiled.match(block.header)
            if match:
                sink.append(match.group(1))
                doc.consume(block)

    collect(r"ntp server\s+(\S+)", services.ntp_servers)
    collect(r"ip name-server\s+(.+)", services.name_servers)
    collect(r"logging server\s+(\S+)", services.logging_hosts)
    collect(r"snmp-server host\s+(\S+)", services.snmp_traps_hosts)
    collect(r"snmp-server user\s+(\S+)", services.snmp_v3_users)
    collect(r"username\s+(\S+)", services.local_users)

    for block in doc.find(r"snmp-server community\s+"):
        services.snmp_communities += 1
        doc.consume(block)
    for block in doc.find(r"ip domain-name\s+"):
        services.domain_name = block.header.split()[-1]
        doc.consume(block)

    for name in ("ntp_servers", "logging_hosts", "snmp_v3_users",
                 "local_users", "snmp_traps_hosts"):
        setattr(services, name, sorted(set(getattr(services, name))))
    return services
