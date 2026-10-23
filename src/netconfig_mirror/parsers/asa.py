"""ASA parser: configuration text -> DeviceModel.

Scoped from a command census of the LAC1 firewall rather than from what an
ASA parser usually covers. That census said something the shape of the file
does not: `crypto` and `tunnel-group` are 245 of its 681 lines, and
`access-list` is 25. This is a VPN head-end that also filters, not a packet
filter that also terminates tunnels, so the VPN is modelled first and in the
most detail.

Two things drive the rest. `nameif` is the join key - NAT pairs,
access-groups and crypto maps name an interface by its nameif and never by
`GigabitEthernet0/0` - and objects are the vocabulary the policy is written
in, so an access-list without them reads as references to nothing.
"""
from __future__ import annotations

import re

from ..blocks import Block, ConfigDocument
from ..model import (
    AccessGroup,
    AccessList,
    CryptoMap,
    CryptoMapEntry,
    Device,
    DeviceModel,
    IkePolicy,
    Interface,
    IpsecProfile,
    IpsecProposal,
    NatRule,
    NetworkObject,
    ObjectGroup,
    Services,
    StaticRoute,
    TunnelGroup,
    Vpn,
)

# Recognised, deliberately not modelled. Counted apart from the coverage
# figure so recognising a line can never be mistaken for understanding it.
_ACKNOWLEDGED = re.compile(
    r"^(?:no\s+)?(?:"
    r":|ASA\b|hostname\b|enable\b|passwd\b|username\b|terminal\b|names?\b"
    r"|banner\b|boot\b|ftp\b|dns\b|same-security-traffic\b|pager\b"
    r"|xlate\b|timeout\b|arp\b|sysopt\b|service\b|clock\b|ntp\b"
    r"|policy-map\b|class-map\b|class\b|prompt\b|call-home\b|webvpn\b"
    r"|group-policy\b|privilege\b|http\b|asdm\b|threat-detection\b"
    r"|console\b|management-access\b|dhcpd\b|mtu\b|monitor-interface\b"
    r"|failover\b|icmp\b|ip\b|ipv6\b|auth-prompt\b|fragment\b|quit\b"
    r"|user-identity\b|subject-name\b|zonelabs\b|vpn-addr-assign\b"
    r"|crypto ca\b|crypto key\b|crypto isakmp\b"
    r"|crypto ipsec (?:security-association|df-bit|fragmentation)\b"
    r"|dynamic-access-policy-record\b|ssl\b|tls-proxy\b|eou\b|aaa\b|aaa-server\b"
    r"|logging\b|snmp-server\b|ssh\b|telnet\b|router\b|end\b|exit\b"
    r")"
)

_OBJECT_VALUE = re.compile(r"^(host|subnet|range|fqdn)\s+(.+)$", re.I)
_CRYPTO_MAP = re.compile(
    r"^crypto map (?P<name>\S+)\s+(?:(?P<seq>\d+)\s+(?P<rest>.+)"
    r"|interface\s+(?P<interface>\S+))$", re.I)
_TUNNEL_GROUP = re.compile(
    r"^tunnel-group (?P<name>\S+) (?P<what>type|general-attributes"
    r"|ipsec-attributes|webvpn-attributes)(?:\s+(?P<value>.+))?$", re.I)
_NAT = re.compile(
    r"^nat\s+\((?P<src>[^,)]+),(?P<dst>[^)]+)\)\s*(?P<rest>.*)$", re.I)


def parse(config_text: str, *, platform: str | None = None,
          os_version: str | None = None) -> tuple[DeviceModel, ConfigDocument]:
    doc = ConfigDocument(config_text)
    model = DeviceModel()

    model.device = _device(doc, platform, os_version)
    model.interfaces = _interfaces(doc)
    model.objects = _objects(doc)
    model.object_groups = _object_groups(doc)
    model.access_lists = _access_lists(doc)
    model.access_groups = _access_groups(doc)
    model.nat = _nat(doc)
    model.static_routes = _routes(doc)
    model.vpn = _vpn(doc)
    model.services = _services(doc)

    _link_references(model)
    _acknowledge_remainder(doc)
    return model, doc


def _device(doc: ConfigDocument, platform: str | None,
            os_version: str | None) -> Device:
    hostname = None
    for block in doc.find(r"hostname\s+"):
        hostname = block.header.split(None, 1)[1].strip()
    if os_version is None:
        for block in doc.find(r"ASA Version\s+"):
            os_version = block.header.split()[2]
    return Device(hostname=hostname, platform=platform, os_version=os_version)


def _interfaces(doc: ConfigDocument) -> list[Interface]:
    interfaces = []
    for block in doc.find(r"interface\s+\S+"):
        interface = Interface(name=block.header.split(None, 1)[1].strip())
        for child in block.children:
            line = child.strip()
            if line.startswith("nameif "):
                interface.nameif = line.split(None, 1)[1]
            elif line.startswith("security-level "):
                interface.security_level = line.split(None, 1)[1]
            elif line.startswith("description "):
                interface.description = line.split(None, 1)[1]
            elif line == "shutdown":
                interface.enabled = False
            elif line.startswith("ip address "):
                parts = line.split()
                interface.ipv4.append(" ".join(parts[2:4]))
                if "standby" in parts:
                    interface.standby_ip = parts[parts.index("standby") + 1]
            elif line.startswith("ipv6 address "):
                interface.ipv6.append(line.split(None, 2)[2])
            elif line.startswith("vlan "):
                interface.access_vlan = line.split(None, 1)[1]
            elif line.startswith("tunnel source "):
                interface.tunnel_source = line.split(None, 2)[2]
            elif line.startswith("tunnel destination "):
                interface.tunnel_destination = line.split(None, 2)[2]
            elif line.startswith("tunnel mode "):
                interface.tunnel_mode = line.split(None, 2)[2]
            elif line.startswith("tunnel protection ipsec profile "):
                interface.tunnel_protection = line.split()[-1]
        interfaces.append(interface)
        doc.consume(block)
    return interfaces


def _objects(doc: ConfigDocument) -> list[NetworkObject]:
    objects = []
    for block in doc.find(r"object (?:network|service)\s+"):
        kind_word, name = block.header.split()[1], block.header.split()[2]
        entry = NetworkObject(name=name)
        for child in block.children:
            line = child.strip()
            if match := _OBJECT_VALUE.match(line):
                entry.kind, entry.value = match.group(1).lower(), match.group(2)
            elif line.startswith("description "):
                entry.description = line.split(None, 1)[1]
            elif line.startswith("service "):
                entry.kind, entry.value = "service", line.split(None, 1)[1]
            elif line.startswith("nat "):
                entry.nat = line
        if kind_word.lower() == "service" and entry.kind is None:
            entry.kind = "service"
        objects.append(entry)
        doc.consume(block)
    return objects


def _object_groups(doc: ConfigDocument) -> list[ObjectGroup]:
    groups = []
    for block in doc.find(r"object-group\s+"):
        parts = block.header.split()
        group = ObjectGroup(name=parts[2] if len(parts) > 2 else parts[1],
                            kind=parts[1].lower() if len(parts) > 2 else None,
                            protocol=parts[3] if len(parts) > 3 else None)
        for child in block.children:
            line = child.strip()
            if line.startswith("description "):
                group.description = line.split(None, 1)[1]
            else:
                group.members.append(line)
        group.member_count = len(group.members)
        groups.append(group)
        doc.consume(block)
    return groups


def _access_lists(doc: ConfigDocument) -> list[AccessList]:
    """One line per entry, unlike IOS, so the list is assembled across blocks."""
    acls: dict[str, AccessList] = {}
    for block in doc.find(r"access-list\s+"):
        parts = block.header.split()
        if len(parts) < 3:
            continue
        name = parts[1]
        acl = acls.setdefault(name, AccessList(name=name))
        if acl.type is None and parts[2] in ("extended", "standard", "ethertype"):
            acl.type = parts[2]
        acl.entries.append(" ".join(parts[2:]))
        acl.entry_count = len(acl.entries)
        doc.consume(block)
    return list(acls.values())


def _access_groups(doc: ConfigDocument) -> list[AccessGroup]:
    groups = []
    for block in doc.find(r"access-group\s+"):
        parts = block.header.split()
        group = AccessGroup(access_list=parts[1])
        if "interface" in parts:
            group.interface = parts[parts.index("interface") + 1]
            group.direction = parts[2]
        elif "global" in parts:
            group.direction = "global"
        groups.append(group)
        doc.consume(block)
    return groups


def _nat(doc: ConfigDocument) -> list[NatRule]:
    rules = []
    for block in doc.find(r"nat\s+\("):
        match = _NAT.match(block.header.strip())
        if not match:
            continue
        rest = match.group("rest").strip()
        words = rest.split()
        rule = NatRule(source_interface=match.group("src").strip(),
                       destination_interface=match.group("dst").strip(),
                       rule=rest)
        if words and words[0] == "after-auto":
            rule.section = "after-auto"
            words = words[1:]
        for word in words:
            if word in ("static", "dynamic"):
                rule.kind = word
                break
        rules.append(rule)
        doc.consume(block)
    return rules


def _routes(doc: ConfigDocument) -> list[StaticRoute]:
    routes = []
    for block in doc.find(r"route\s+\S+\s+\d"):
        parts = block.header.split()
        if len(parts) < 5:
            continue
        # The ASA names the egress interface by nameif where IOS does not,
        # and it belongs with the route rather than being dropped: two default
        # routes out of different interfaces are the normal shape here.
        routes.append(StaticRoute(prefix=f"{parts[2]} {parts[3]}",
                                  next_hop=parts[4],
                                  interface=parts[1],
                                  distance=parts[5] if len(parts) > 5 else None))
        doc.consume(block)
    return routes


def _vpn(doc: ConfigDocument) -> Vpn | None:
    vpn = Vpn()
    _ike_policies(doc, vpn)
    _proposals(doc, vpn)
    _ipsec_profiles(doc, vpn)
    _crypto_maps(doc, vpn)
    _tunnel_groups(doc, vpn)

    for block in doc.find(r"crypto ikev[12] enable\s+"):
        vpn.enabled_on.append(block.header.split()[3])
        doc.consume(block)

    if not any((vpn.enabled_on, vpn.ike_policies, vpn.ipsec_proposals,
                vpn.ipsec_profiles, vpn.crypto_maps, vpn.tunnel_groups)):
        return None
    return vpn


def _ike_policies(doc: ConfigDocument, vpn: Vpn) -> None:
    for block in doc.find(r"crypto ikev[12] policy\s+"):
        parts = block.header.split()
        policy = IkePolicy(version=parts[1].lower(), priority=parts[3])
        for child in block.children:
            words = child.strip().split(None, 1)
            if len(words) != 2:
                continue
            field_name, value = words[0].lower(), words[1]
            if field_name == "authentication":
                policy.authentication = value
            elif field_name == "encryption":
                policy.encryption = value
            elif field_name in ("hash", "integrity"):
                policy.integrity = value
            elif field_name == "group":
                policy.group = value
            elif field_name == "prf":
                policy.prf = value
            elif field_name == "lifetime":
                policy.lifetime = value
        vpn.ike_policies.append(policy)
        doc.consume(block)


def _proposals(doc: ConfigDocument, vpn: Vpn) -> None:
    for block in doc.find(r"crypto ipsec ikev1 transform-set\s+"):
        parts = block.header.split()
        vpn.ipsec_proposals.append(
            IpsecProposal(name=parts[4], version="ikev1", transforms=parts[5:]))
        doc.consume(block)

    for block in doc.find(r"crypto ipsec ikev2 ipsec-proposal\s+"):
        proposal = IpsecProposal(name=block.header.split()[4], version="ikev2")
        proposal.transforms = [child.strip() for child in block.children]
        vpn.ipsec_proposals.append(proposal)
        doc.consume(block)


def _ipsec_profiles(doc: ConfigDocument, vpn: Vpn) -> None:
    for block in doc.find(r"crypto ipsec profile\s+"):
        profile = IpsecProfile(name=block.header.split()[3])
        for child in block.children:
            words = child.strip().split()
            if words[:3] == ["set", "ikev1", "transform-set"]:
                profile.ikev1_transform_sets.extend(words[3:])
            elif words[:3] == ["set", "ikev2", "ipsec-proposal"]:
                profile.ikev2_proposals.extend(words[3:])
            elif words[:2] == ["set", "pfs"]:
                profile.pfs = words[2] if len(words) > 2 else "enabled"
            elif words[:4] == ["set", "security-association", "lifetime", "seconds"]:
                profile.lifetime = words[4]
        vpn.ipsec_profiles.append(profile)
        doc.consume(block)


def _crypto_maps(doc: ConfigDocument, vpn: Vpn) -> None:
    """Assembled across lines: an ASA writes one `crypto map NAME SEQ ...` per
    setting, so a single tunnel is spread over five or six separate blocks."""
    maps: dict[str, CryptoMap] = {}
    entries: dict[tuple[str, str], CryptoMapEntry] = {}

    for block in doc.find(r"crypto map\s+"):
        match = _CRYPTO_MAP.match(block.header.strip())
        if not match:
            continue
        crypto_map = maps.setdefault(match.group("name"),
                                     CryptoMap(name=match.group("name")))
        if match.group("interface"):
            crypto_map.interface = match.group("interface")
            doc.consume(block)
            continue

        key = (match.group("name"), match.group("seq"))
        entry = entries.get(key)
        if entry is None:
            entry = CryptoMapEntry(seq=match.group("seq"))
            entries[key] = entry
            crypto_map.entries.append(entry)

        rest = match.group("rest").split()
        if rest[:2] == ["match", "address"]:
            entry.match_address = rest[2]
        elif rest[:2] == ["set", "peer"]:
            entry.peers.extend(rest[2:])
        elif rest[:3] == ["set", "ikev1", "transform-set"]:
            entry.ikev1_transform_sets.extend(rest[3:])
        elif rest[:3] == ["set", "ikev2", "ipsec-proposal"]:
            entry.ikev2_proposals.extend(rest[3:])
        elif rest[:2] == ["set", "pfs"]:
            entry.pfs = rest[2] if len(rest) > 2 else "enabled"
        elif rest[:4] == ["set", "security-association", "lifetime", "seconds"]:
            entry.lifetime = rest[4]
        doc.consume(block)

    for crypto_map in maps.values():
        crypto_map.entries.sort(key=lambda e: int(e.seq))
    vpn.crypto_maps.extend(maps.values())


def _tunnel_groups(doc: ConfigDocument, vpn: Vpn) -> None:
    groups: dict[str, TunnelGroup] = {}

    for block in doc.find(r"tunnel-group\s+"):
        match = _TUNNEL_GROUP.match(block.header.strip())
        if not match:
            continue
        group = groups.setdefault(match.group("name"),
                                  TunnelGroup(name=match.group("name")))
        what = match.group("what").lower()
        if what == "type":
            group.type = match.group("value")
        for child in block.children:
            line = child.strip()
            if line.startswith("default-group-policy "):
                group.default_group_policy = line.split(None, 1)[1]
            elif "pre-shared-key" in line:
                group.has_pre_shared_key = True
                if line.startswith("ikev2 local-authentication"):
                    group.ikev2_local_authentication = "pre-shared-key"
                elif line.startswith("ikev2 remote-authentication"):
                    group.ikev2_remote_authentication = "pre-shared-key"
        doc.consume(block)

    vpn.tunnel_groups.extend(groups.values())


def _services(doc: ConfigDocument) -> Services:
    services = Services()
    for block in doc.find(r"logging host\s+"):
        services.logging_hosts.append(block.header.split()[-1])
        doc.consume(block)
    for block in doc.find(r"ntp server\s+"):
        services.ntp_servers.append(block.header.split()[2])
        doc.consume(block)
    for block in doc.find(r"snmp-server host\s+"):
        services.snmp_traps_hosts.append(block.header.split()[3])
        doc.consume(block)
    return services


def _link_references(model: DeviceModel) -> None:
    """Who refers to what. Computed rather than parsed, and the point of
    modelling objects at all: a group nothing references announces nothing,
    and a tunnel-group no crypto map points at is a peer that was never wired
    up."""
    objects = {obj.name: obj for obj in model.objects}
    groups = {group.name: group for group in model.object_groups}

    def _note(name: str, where: str) -> None:
        if target := objects.get(name) or groups.get(name):
            if where not in target.referenced_by:
                target.referenced_by.append(where)

    for acl in model.access_lists:
        for entry in acl.entries:
            words = entry.split()
            for index, word in enumerate(words):
                if word in ("object", "object-group") and index + 1 < len(words):
                    _note(words[index + 1], f"access-list {acl.name}")

    for rule in model.nat:
        for word in rule.rule.split():
            _note(word, f"nat ({rule.source_interface},"
                        f"{rule.destination_interface})")

    for group in model.object_groups:
        for member in group.members:
            words = member.split()
            if words[:1] == ["group-object"] and len(words) > 1:
                _note(words[1], f"object-group {group.name}")
            elif words[:2] == ["network-object", "object"] and len(words) > 2:
                _note(words[2], f"object-group {group.name}")

    if model.vpn:
        peers: dict[str, list[str]] = {}
        for crypto_map in model.vpn.crypto_maps:
            for entry in crypto_map.entries:
                for peer in entry.peers:
                    peers.setdefault(peer, []).append(
                        f"crypto map {crypto_map.name} {entry.seq}")
        for group in model.vpn.tunnel_groups:
            group.referenced_by = peers.get(group.name, [])

        profiles = {p.name: p for p in model.vpn.ipsec_profiles}
        for interface in model.interfaces:
            if not interface.tunnel_protection:
                continue
            profile = profiles.get(interface.tunnel_protection)
            if profile is not None:
                profile.referenced_by.append(f"interface {interface.name}")


def _acknowledge_remainder(doc: ConfigDocument) -> None:
    for block in doc.blocks:
        if _ACKNOWLEDGED.match(block.header.strip()):
            doc.acknowledge(block)
