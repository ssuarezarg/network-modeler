"""Volatile-line filtering and provenance extraction.

This is the stage that decides whether the mirror is readable. Captured configs
carry lines that change with no operator action - timestamps, checksums, byte
counts. Left in, every sync produces a commit, the real changes drown in noise,
and within a month nobody reads the diffs. A mirror that always shows changes is
worth exactly as much as one that never does.

So the content that gets hashed and committed excludes them. The information is
not thrown away: the useful parts (who last changed the device and when, serial,
hardware) move into the per-device `meta.yaml` as provenance, which is only
rewritten when the content itself changed.

Observed in the LAC1 captures:
  ! Last configuration change at 11:45:33 EST Wed Sep 2 2026 by someone@example
  ! NVRAM config last updated at 15:18:18 EST Mon Aug 31 2026 by other@example
  Cryptochecksum:....  (ASA)
  : Serial Number: ....  /  : Hardware: ....  (ASA header)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Split on CR/LF only.
#
# str.splitlines() also breaks on form feed, vertical tab, \x85 and \u2028. A
# banner containing ^L -- common in legacy MOTD banners -- would be split into
# bogus lines and silently corrupt the mirrored config. The collector does not
# normalise line endings (they come from Netmiko and vary by vendor), so the
# input really can contain any of these.
_LINE_SPLIT = re.compile(r"\r\n|\r|\n")

_LAST_CHANGE = re.compile(
    r"^\s*!\s*Last configuration change at (?P<when>.+?)(?:\s+by\s+(?P<who>\S+))?\s*$", re.I)
_NVRAM_UPDATE = re.compile(
    r"^\s*!\s*NVRAM config last updated at (?P<when>.+?)(?:\s+by\s+(?P<who>\S+))?\s*$", re.I)
_SERIAL = re.compile(r"^\s*:\s*Serial Number:\s*(?P<serial>\S+)", re.I)
_HARDWARE = re.compile(r"^\s*:\s*Hardware:\s*(?P<hardware>.+?)\s*$", re.I)

# Dropped outright: no provenance value, pure churn.
_VOLATILE = [
    # A digest of the pre-redaction config. After redaction it matches nothing,
    # so keeping it can only mislead a reader into thinking it verifies something.
    re.compile(r"^\s*Cryptochecksum:", re.I),
    re.compile(r"^\s*ntp clock-period\b", re.I),
    re.compile(r"^\s*Building configuration", re.I),
    # Byte count changes with any edit, including ones we redact away.
    # The leading `!` is optional: real captures emit this line both ways, and
    # requiring it let the byte count through into the stored configuration,
    # where it would disagree with the file we actually write.
    re.compile(r"^\s*!?\s*Current configuration\s*:\s*\d+ bytes", re.I),
    re.compile(r"^\s*!\s*Time source is", re.I),
    # NX-OS capture header. `!Time:` carries the moment of capture and changes
    # on every single run - left in, no NX-OS device would ever look unchanged.
    re.compile(r"^\s*!Time:", re.I),
    re.compile(r"^\s*!Command:", re.I),
    re.compile(r"^\s*!Running configuration last done at:", re.I),
    re.compile(r"^\s*!Startup config saved at:", re.I),
    re.compile(r"^\s*!No configuration change since last restart", re.I),
    re.compile(r"^\s*!\s*Last configuration change", re.I),
    re.compile(r"^\s*!\s*NVRAM config last updated", re.I),
]


@dataclass
class Provenance:
    last_changed_at: str | None = None
    last_changed_by: str | None = None
    nvram_updated_at: str | None = None
    serial: str | None = None
    hardware: str | None = None
    dropped_lines: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], 0)}


def normalize(
    config_text: str,
    *,
    keep_email_domain: bool = False,
) -> tuple[str, Provenance]:
    """Strip volatile lines; return stable content plus extracted provenance.

    `keep_email_domain=False` (the default) reduces `user@customer.example` to
    `user` in the recorded author. The local part is enough to answer "who
    touched this device"; propagating full addresses of customer staff into a
    stored file is personal data we have no need to keep. Set True only if the
    audit requirement is explicit.
    """
    provenance = Provenance()
    kept: list[str] = []

    for raw_line in _LINE_SPLIT.split(config_text):
        line = raw_line.rstrip()

        if match := _LAST_CHANGE.match(line):
            provenance.last_changed_at = match.group("when").strip()
            provenance.last_changed_by = _clean_author(match.group("who"), keep_email_domain)
            provenance.dropped_lines += 1
            continue

        if match := _NVRAM_UPDATE.match(line):
            provenance.nvram_updated_at = match.group("when").strip()
            provenance.dropped_lines += 1
            continue

        if match := _SERIAL.match(line):
            provenance.serial = match.group("serial")
            provenance.dropped_lines += 1
            continue

        if match := _HARDWARE.match(line):
            provenance.hardware = match.group("hardware")
            provenance.dropped_lines += 1
            continue

        if any(pattern.match(line) for pattern in _VOLATILE):
            provenance.dropped_lines += 1
            continue

        kept.append(line)

    # Collapse the blank-line runs that removals leave behind, and guarantee a
    # single trailing newline: otherwise a capture that differs only in trailing
    # whitespace shows up as a change.
    text = _collapse_blank_runs(kept)
    return text, provenance


def _clean_author(who: str | None, keep_domain: bool) -> str | None:
    if not who:
        return None
    who = who.strip()
    if not keep_domain and "@" in who:
        return who.split("@", 1)[0]
    return who


def _collapse_blank_runs(lines: list[str]) -> str:
    out: list[str] = []
    for line in lines:
        if not line.strip() and out and not out[-1].strip():
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n" if out else ""
