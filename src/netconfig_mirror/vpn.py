"""Every IPsec endpoint in the estate, and how each one is reached.

Written for a question the mirror could not answer before the ASA was
modelled: when a site relocates, which remote parties terminate a tunnel on
its equipment, and what does each of them have to be told.

The answer is not one list. A tunnel is built in one of two ways, they look
nothing alike in the configuration, and a survey that knows only one of them
misses the other entirely:

* **Policy-based** — a crypto map matches an access-list and sets a peer.
* **Route-based (VTI)** — a tunnel interface carries `tunnel destination`
  and an IPsec profile, and no access-list is involved.

Both authenticate against a tunnel-group named after the peer, which is the
one thing they share and what lets them be reported together.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .analysis import DeviceDoc


@dataclass
class Endpoint:
    device: str
    path: str
    peer: str
    style: str                      # policy-based | route-based
    local_interface: str | None = None
    detail: str | None = None
    has_pre_shared_key: bool = False
    # Set when the tunnel-group for this peer is missing: the tunnel is
    # configured but has nothing to authenticate with.
    missing_tunnel_group: bool = False


@dataclass
class DeviceEndpoints:
    device: str
    path: str
    endpoints: list[Endpoint] = field(default_factory=list)
    # Tunnel-groups with no tunnel pointing at them. Reported beside the
    # endpoints rather than in the audit, because during a relocation a peer
    # that was decommissioned and a peer that was never wired up are the same
    # question: is anyone on the far end expecting this?
    unused_peers: list[str] = field(default_factory=list)


def collect(devices: list[DeviceDoc]) -> list[DeviceEndpoints]:
    out = []
    for device in devices:
        vpn = device.vpn
        if not vpn:
            continue
        groups = {g["name"]: g for g in vpn.get("tunnel_groups", [])}
        entry = DeviceEndpoints(device=device.hostname, path=device.path)

        for crypto_map in vpn.get("crypto_maps", []):
            for item in crypto_map.get("entries", []):
                for peer in item.get("peers", []):
                    entry.endpoints.append(Endpoint(
                        device=device.hostname, path=device.path, peer=peer,
                        style="policy-based",
                        local_interface=crypto_map.get("interface"),
                        detail=f"crypto map {crypto_map['name']} {item.get('seq')}"
                               f", matches {item.get('match_address') or '(nothing)'}",
                        has_pre_shared_key=bool(
                            groups.get(peer, {}).get("has_pre_shared_key")),
                        missing_tunnel_group=peer not in groups))

        profiles = {p["name"]: p for p in vpn.get("ipsec_profiles", [])}
        for interface in device.data.get("interfaces", []):
            peer = interface.get("tunnel_destination")
            if not peer:
                continue
            profile = interface.get("tunnel_protection")
            entry.endpoints.append(Endpoint(
                device=device.hostname, path=device.path, peer=peer,
                style="route-based",
                local_interface=interface.get("nameif") or interface["name"],
                detail=f"{interface['name']} via profile {profile or '(none)'}"
                       + ("" if profile in profiles else " [profile not defined]"),
                has_pre_shared_key=bool(
                    groups.get(peer, {}).get("has_pre_shared_key")),
                missing_tunnel_group=peer not in groups))

        reached = {e.peer for e in entry.endpoints}
        entry.unused_peers = sorted(name for name in groups if name not in reached)
        if entry.endpoints or entry.unused_peers:
            out.append(entry)
    return out


def render(collected: list[DeviceEndpoints]) -> str:
    total = sum(len(d.endpoints) for d in collected)
    lines = [f"# IPsec endpoints — {total} tunnel(s) on {len(collected)} device(s)",
             "",
             "Every remote party that terminates a tunnel on this estate. During a",
             "site move each one is a counterparty: the tunnel survives the move",
             "only if the local public address survives it, and needs coordinating",
             "if it does not.",
             ""]

    for device in sorted(collected, key=lambda d: d.path):
        lines += [f"## {device.device}  [{device.path}]", ""]
        if not device.endpoints:
            lines += ["  no tunnel is built on this device", ""]
        for endpoint in sorted(device.endpoints, key=lambda e: (e.style, e.peer)):
            flags = []
            if not endpoint.has_pre_shared_key:
                flags.append("no pre-shared key")
            if endpoint.missing_tunnel_group:
                flags.append("NO TUNNEL-GROUP")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(f"  {endpoint.peer:<18} {endpoint.style:<13} "
                         f"out {endpoint.local_interface or '?':<10} "
                         f"{endpoint.detail}{suffix}")
        if device.unused_peers:
            lines += ["",
                      "  tunnel-groups no tunnel points at — ask whether the far "
                      "end still expects them:"]
            lines += [f"    {name}" for name in device.unused_peers]
        lines.append("")

    peers = sorted({e.peer for d in collected for e in d.endpoints})
    lines += [f"## {len(peers)} distinct remote endpoint(s)", ""]
    lines += [f"  {peer}" for peer in peers]
    return "\n".join(lines) + "\n"
