"""Mirroring JSON captures — Firepower via FMC.

Firepower has no flat configuration. Its state arrives as several REST endpoints
(`fmc_acp`, `fmc_nat`, `fmc_interfaces`, `fmc_routes`, `fmc_device_detail`),
almost certainly JSON, and each is a separate row. Three things differ from
mirroring CLI text, and each is a way to get this wrong:

**Rendering must be canonical.** Two reads of the same policy can serialise with
different key order or spacing and be the same policy. Sorting keys and fixing
the indentation makes the diff mean something.

**Volatile fields must be found, not guessed.** REST responses carry timestamps,
counters and per-read identifiers. Left in, every sync commits every firewall
every night — the same churn `!Time:` would have caused on NX-OS, with far more
surface to hide in. `find_volatile` compares two captures of the same endpoint
and reports the paths that moved, so the list comes from evidence.

**Secrets hide differently.** The line-oriented redaction rules are shaped for
Cisco CLI and match almost nothing in JSON: `"password": "hunter2"` sails
straight past them. Redaction here walks the structure and replaces values whose
*key* names a credential, and the audit looks for the same thing — otherwise the
fail-closed guarantee simply would not apply to a third of the estate.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .redact import is_upstream_sanitised, token

# Key names whose value is a credential. Matched on the whole key, case
# insensitively, so `keyword` and `publicKey` are not caught by `key`.
_SENSITIVE_KEY = re.compile(
    r"^(?:.*_)?(?:password|passwd|secret|psk|pre_?shared_?key|shared_?secret"
    r"|community|auth_?key|priv_?key|private_?key|token|credential|passphrase"
    r"|snmp_?community|enable_?password)$",
    re.I,
)

# Paths known to move on every read regardless of configuration. Deliberately
# short: the rest belong in a per-deployment list built from `find_volatile`,
# because guessing which fields are volatile is how a daily empty commit starts.
DEFAULT_VOLATILE = (
    "metadata.timestamp",
    "metadata.lastUser",
    "links.self",
    "paging",
    # Measured, not assumed: comparing two captures of a real Firepower a day
    # apart, this was the only field that moved across all five endpoints.
    #
    # It is not noise — it says whether FMC holds changes that have not been
    # deployed, which is genuine drift between intent and what the device runs.
    # But it is operational state rather than configuration, so it belongs in a
    # report like staleness does, not in the content whose diff is the product.
    # Left in, it would commit a firewall every time someone staged a change.
    "deploymentStatus",
)


@dataclass
class JsonRedactionReport:
    redacted: int = 0
    upstream_sanitised: int = 0
    residuals: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.residuals


def parse(text: str):
    """Return the parsed structure, or None when the capture is not JSON."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def render(obj) -> str:
    """Canonical JSON: sorted keys, fixed indentation, one trailing newline.

    Two reads of the same policy must produce identical bytes, or the mirror
    reports a change that did not happen.
    """
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _walk(obj, path: str, visit):
    if isinstance(obj, dict):
        return {k: _walk(v, f"{path}.{k}" if path else k, visit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, f"{path}[]", visit) for v in obj]
    return visit(obj, path)


def redact(obj, key: bytes) -> tuple[object, JsonRedactionReport]:
    """Replace values whose key names a credential."""
    report = JsonRedactionReport()

    def visit(value, path: str):
        leaf = path.split(".")[-1].replace("[]", "")
        if not _SENSITIVE_KEY.match(leaf) or not isinstance(value, str) or not value:
            return value
        if is_upstream_sanitised(value):
            report.upstream_sanitised += 1
            return value
        report.redacted += 1
        return token(value, key)

    return _walk(obj, "", visit), report


def audit_residuals(obj) -> list[str]:
    """Credential-named fields that came through without a token.

    The CLI rules cannot see these: `"password": "hunter2"` matches none of
    them. Without this, a third of the estate would have no fail-closed check at
    all.
    """
    residuals: list[str] = []

    def visit(value, path: str):
        leaf = path.split(".")[-1].replace("[]", "")
        if (_SENSITIVE_KEY.match(leaf) and isinstance(value, str) and value
                and "<redacted:" not in value
                and "[OMITTED_BY_SANITIZER]" not in value):
            residuals.append(path)
        return value

    _walk(obj, "", visit)
    return residuals


def strip_volatile(obj, paths=DEFAULT_VOLATILE):
    """Remove fields that move on every read."""
    wanted = set(paths)

    def visit(value, path: str):
        return None if path.replace("[]", "") in wanted else value

    def prune(node, path: str):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                child = f"{path}.{k}" if path else k
                if child.replace("[]", "") in wanted:
                    continue
                out[k] = prune(v, child)
            return out
        if isinstance(node, list):
            return [prune(v, f"{path}[]") for v in node]
        return node

    return prune(obj, "")


def find_volatile(first, second, *, path: str = "") -> list[str]:
    """Paths that differ between two captures of the same endpoint.

    The honest way to build a volatile-field list: take two captures taken apart
    in time with no configuration change between them, and see what moved.
    Guessing produces either a daily empty commit or a silently dropped field.
    """
    differing: list[str] = []

    if type(first) is not type(second):
        return [path or "<root>"]

    if isinstance(first, dict):
        for key in sorted(set(first) | set(second)):
            child = f"{path}.{key}" if path else key
            if key not in first or key not in second:
                differing.append(child)
            else:
                differing += find_volatile(first[key], second[key], path=child)
        return differing

    if isinstance(first, list):
        if len(first) != len(second):
            return [f"{path}[] (length {len(first)} vs {len(second)})"]
        for index, (a, b) in enumerate(zip(first, second)):
            differing += find_volatile(a, b, path=f"{path}[]")
        return sorted(set(differing))

    return [] if first == second else [path or "<root>"]
