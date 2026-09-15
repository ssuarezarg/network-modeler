"""Questions about the mirror that a text diff answers badly.

Two of them, both about routing policy, both found by hand first and therefore
worth making automatic:

`compare` puts two devices side by side. A redundant pair is supposed to differ
- different loopbacks, different peering addresses, deliberate traffic
  engineering - so a raw diff of two device.yaml files is thousands of lines in
  which the one real finding is buried. This reports the shape of the
  difference instead of the text of it.

`audit` looks for policy that cannot do what it appears to do: prefix-lists that
nothing references, and route-maps that match a prefix-list which does not
exist. The second is the more dangerous. A route-map matching a name with a typo
in it does not fail loudly; it silently matches nothing, and the policy the
engineer believed they were applying was never applied at all.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .layout import ROOT

# Names this close are more likely one name typed twice than two intended names.
_SIMILAR_ENOUGH = 0.82


@dataclass
class DeviceDoc:
    hostname: str
    path: str
    data: dict

    @property
    def prefix_lists(self) -> dict[str, dict]:
        return {p["name"]: p for p in self.data.get("prefix_lists", [])}

    @property
    def route_maps(self) -> dict[str, dict]:
        return {m["name"]: m for m in self.data.get("route_maps", [])}


def load_devices(repo: str | Path) -> list[DeviceDoc]:
    root = Path(repo) / ROOT
    docs = []
    for path in sorted(root.glob("*/*/device.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        hostname = (data.get("device") or {}).get("hostname") or path.parent.name
        docs.append(DeviceDoc(hostname=hostname,
                              path=str(path.parent.relative_to(repo)), data=data))
    return docs


def find_device(devices: list[DeviceDoc], name: str) -> DeviceDoc | None:
    wanted = name.strip().lower()
    for device in devices:
        if device.hostname.lower() == wanted or device.path.lower().endswith("/" + wanted):
            return device
    for device in devices:
        if wanted in device.hostname.lower() or wanted in device.path.lower():
            return device
    return None


def _entry_set(prefix_list: dict) -> set[tuple]:
    """Entries without their sequence numbers.

    Two lists holding the same entries at different sequence numbers are usually
    - not always - the same policy. Reporting that separately from a genuine
    content difference keeps the signal honest: renumbering is worth a glance,
    a different prefix is worth attention.
    """
    return {
        (e.get("action"), e.get("prefix"), e.get("ge"), e.get("le"))
        for e in prefix_list.get("entries", [])
    }


@dataclass
class Comparison:
    only_a: list[str] = field(default_factory=list)
    only_b: list[str] = field(default_factory=list)
    identical: list[str] = field(default_factory=list)
    resequenced: list[str] = field(default_factory=list)
    differing: list[tuple[str, list[str], list[str]]] = field(default_factory=list)
    possible_typos: list[tuple[str, str]] = field(default_factory=list)


def compare_policy(a: DeviceDoc, b: DeviceDoc) -> Comparison:
    result = Comparison()
    lists_a, lists_b = a.prefix_lists, b.prefix_lists

    for name in sorted(set(lists_a) | set(lists_b)):
        if name not in lists_b:
            result.only_a.append(name)
        elif name not in lists_a:
            result.only_b.append(name)
        else:
            entries_a = _entry_set(lists_a[name])
            entries_b = _entry_set(lists_b[name])
            if entries_a != entries_b:
                result.differing.append((
                    name,
                    sorted(f"{e[0]} {e[1]}" for e in entries_a - entries_b),
                    sorted(f"{e[0]} {e[1]}" for e in entries_b - entries_a),
                ))
            elif lists_a[name].get("entries") == lists_b[name].get("entries"):
                result.identical.append(name)
            else:
                result.resequenced.append(name)

    # A name present on only one side that closely resembles a name present on
    # only the other is the signature of a typo, not of two intended policies.
    for name in result.only_a:
        close = difflib.get_close_matches(name, result.only_b, n=1, cutoff=_SIMILAR_ENOUGH)
        if close:
            result.possible_typos.append((name, close[0]))

    return result


def render_comparison(a: DeviceDoc, b: DeviceDoc, result: Comparison) -> str:
    lines = [f"# Routing policy: {a.hostname} vs {b.hostname}", ""]

    if result.possible_typos:
        lines += ["## Names that look like a typo", "",
                  "One of these is probably the other, mistyped. A route-map "
                  "matching the wrong name",
                  "does not fail — it matches nothing, and the policy is never "
                  "applied.", ""]
        for left, right in result.possible_typos:
            lines.append(f"  {a.hostname}: {left}")
            lines.append(f"  {b.hostname}: {right}")
            lines.append("")

    lines += [f"**{len(result.identical)} identical, "
              f"{len(result.resequenced)} resequenced, "
              f"{len(result.differing)} differing, "
              f"{len(result.only_a)} only on {a.hostname}, "
              f"{len(result.only_b)} only on {b.hostname}**", ""]

    if result.only_a:
        lines += [f"## Only on {a.hostname}", ""] + [f"  {n}" for n in result.only_a] + [""]
    if result.only_b:
        lines += [f"## Only on {b.hostname}", ""] + [f"  {n}" for n in result.only_b] + [""]

    if result.differing:
        lines += ["## Same name, different entries", ""]
        for name, missing_in_b, missing_in_a in result.differing:
            lines.append(f"### {name}")
            for entry in missing_in_b:
                lines.append(f"  only {a.hostname}:  {entry}")
            for entry in missing_in_a:
                lines.append(f"  only {b.hostname}:  {entry}")
            lines.append("")

    if result.resequenced:
        lines += ["## Same entries, different sequence numbers", "",
                  "Usually equivalent — but sequence decides evaluation order, so "
                  "it matters",
                  "wherever two entries overlap.", ""]
        lines += [f"  {n}" for n in result.resequenced] + [""]

    return "\n".join(lines) + "\n"


@dataclass
class Finding:
    hostname: str
    kind: str
    detail: str


DANGLING = "route-map matches a prefix-list that does not exist"
ORPHANED = "prefix-list referenced by nothing"


def audit(devices: list[DeviceDoc]) -> list[Finding]:
    findings: list[Finding] = []

    for device in devices:
        lists = device.prefix_lists

        for route_map in device.route_maps.values():
            for name in route_map.get("prefix_lists", []):
                if name not in lists:
                    suggestion = difflib.get_close_matches(
                        name, list(lists), n=1, cutoff=_SIMILAR_ENOUGH)
                    hint = f" (did you mean {suggestion[0]}?)" if suggestion else ""
                    findings.append(Finding(
                        device.hostname, DANGLING,
                        f"{route_map['name']} matches {name}{hint}"))

        for prefix_list in lists.values():
            if not prefix_list.get("referenced_by"):
                findings.append(Finding(
                    device.hostname, ORPHANED,
                    f"{prefix_list['name']} ({prefix_list.get('entry_count', 0)} entries)"))

    return findings


def render_audit(findings: list[Finding], devices: list[DeviceDoc]) -> str:
    lines = [f"# Routing policy audit — {len(devices)} device(s)", ""]

    dangling = [f for f in findings if f.kind == DANGLING]
    orphaned = [f for f in findings if f.kind == ORPHANED]

    lines += ["## Route-maps matching a prefix-list that does not exist", ""]
    if dangling:
        lines += [
            "This is the one worth acting on. A route-map matching a name that",
            "does not exist does not fail — it matches nothing. Whatever policy",
            "was intended is not being applied, and nothing reports it.",
            "",
        ]
        for finding in dangling:
            lines.append(f"  {finding.hostname:<24} {finding.detail}")
    else:
        lines.append("  None.")
    lines.append("")

    lines += ["## Prefix-lists nothing references", ""]
    if orphaned:
        lines += ["Inert: entries that announce and filter nothing. Usually the "
                  "remains of a",
                  "change that was never finished.", ""]
        by_host: dict[str, list[str]] = {}
        for finding in orphaned:
            by_host.setdefault(finding.hostname, []).append(finding.detail)
        for hostname, details in sorted(by_host.items()):
            lines.append(f"  {hostname}  ({len(details)})")
            for detail in details:
                lines.append(f"      {detail}")
    else:
        lines.append("  None.")
    lines.append("")

    return "\n".join(lines) + "\n"
