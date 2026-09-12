"""Survey the estate: what is in the database, and what is wrong with it.

Exists so the questions that shape the mirror can be answered by running the
tool rather than by someone pasting SQL into psql. Three of them decide real
design points:

* **How is a datacenter represented?** `devices.location` is free text with no
  catalogue behind it. If it is populated and consistent, grouping by site is
  trivial; if it is empty, the datacenter has to come from a hostname
  convention (`dc4-`, `am5-`, `sv2-`, `UK-LD5-`, `SG-SG2-`, `HK1-`).
* **Do hostnames collide?** The tenants are organisations merging into one, and
  merging organisations routinely have two devices called `core-sw1`. A mirror
  path keyed on hostname alone would collapse them into one directory, and the
  failure is silent: no error, just one device that appears to reconfigure
  itself completely every day.
* **Which platforms are actually present?** Choosing the next parser from a
  sample rather than from the estate wastes work - an ASA parser was nearly
  written for an estate containing no ASA at all.

It also surfaces captures that are too small to be configurations. Devices
reporting successful collection while storing a 65-byte error string exist here,
and nothing upstream notices.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .extract import all_config_commands

# Below this, a stored "configuration" is an error string, a truncated capture,
# or nothing at all. A real running-config is thousands of bytes; the smallest
# genuine one seen in this estate was ~11 KB.
SUSPICIOUS_CAPTURE_BYTES = 1000

BY_PLATFORM = """
SELECT COALESCE(d.vendor, '(unset)') AS vendor, count(*) AS devices
  FROM devices d
 GROUP BY d.vendor
 ORDER BY devices DESC
"""

BY_LOCATION = """
SELECT COALESCE(d.location, '(unset)') AS location, count(*) AS devices
  FROM devices d
 GROUP BY d.location
 ORDER BY devices DESC
"""

BY_COLLECTOR = """
SELECT COALESCE(d.collector_id, '(unset)') AS collector_id, count(*) AS devices
  FROM devices d
 GROUP BY d.collector_id
 ORDER BY devices DESC
"""

HOSTNAME_COLLISIONS = """
SELECT d.hostname, count(*) AS devices,
       string_agg(DISTINCT COALESCE(d.collector_id, '(unset)'), ', ') AS collectors,
       string_agg(DISTINCT COALESCE(d.location, '(unset)'), ', ') AS locations
  FROM devices d
 WHERE d.hostname IS NOT NULL
 GROUP BY d.hostname
HAVING count(*) > 1
 ORDER BY devices DESC, d.hostname
"""

# Latest capture per device, with its size. LATERAL keeps this to one row per
# device instead of sorting the whole history.
CAPTURE_SIZES = """
SELECT d.hostname, d.vendor, d.location, d.collector_id,
       r.bytes, r.collected_at
  FROM devices d
  JOIN LATERAL (
       SELECT length(ro.output) AS bytes, ro.collected_at
         FROM raw_outputs ro
        WHERE ro.device_id = d.id
          AND ro.command = ANY(%(commands)s)
        ORDER BY ro.collected_at DESC
        LIMIT 1
  ) r ON true
 ORDER BY r.bytes ASC
"""


@dataclass
class Survey:
    by_platform: list[tuple[str, int]] = field(default_factory=list)
    by_location: list[tuple[str, int]] = field(default_factory=list)
    by_collector: list[tuple[str, int]] = field(default_factory=list)
    collisions: list[tuple] = field(default_factory=list)
    captures: list[tuple] = field(default_factory=list)

    @property
    def location_is_usable(self) -> bool:
        """Whether `location` can drive the repository layout.

        Everything landing under one value - usually '(unset)' - means it
        cannot, and the datacenter has to come from hostnames instead.
        """
        if not self.by_location:
            return False
        total = sum(count for _, count in self.by_location)
        unset = sum(count for name, count in self.by_location if name == "(unset)")
        return total > 0 and unset / total < 0.5 and len(self.by_location) > 1

    @property
    def suspicious_captures(self) -> list[tuple]:
        return [row for row in self.captures if row[4] < SUSPICIOUS_CAPTURE_BYTES]


def survey(connection) -> Survey:
    result = Survey()
    with connection.cursor() as cursor:
        cursor.execute(BY_PLATFORM)
        result.by_platform = list(cursor.fetchall())
        cursor.execute(BY_LOCATION)
        result.by_location = list(cursor.fetchall())
        cursor.execute(BY_COLLECTOR)
        result.by_collector = list(cursor.fetchall())
        cursor.execute(HOSTNAME_COLLISIONS)
        result.collisions = list(cursor.fetchall())
        cursor.execute(CAPTURE_SIZES, {"commands": all_config_commands()})
        result.captures = list(cursor.fetchall())
    return result


def datacenter_from_hostname(hostname: str | None) -> str | None:
    """Best-effort datacenter from a hostname, for when `location` is unusable.

    The convention in this estate puts the site first, separated by `-` or `_`:
    `dc4-edge-r1`, `UK-LD5-R316-SW1`, `sv2-r705-l3-sw1`, `SG-SG2-R1`. Two-letter
    country prefixes are kept with the segment that follows, since `UK` alone
    names a country rather than a datacenter.

    Deliberately a guess, and named so. It is a fallback, not a source of truth:
    if `location` is populated, use that.
    """
    if not hostname:
        return None

    parts = [p for p in hostname.replace("_", "-").split("-") if p]
    if not parts:
        return None

    first = parts[0].lower()
    if len(first) == 2 and first.isalpha() and len(parts) > 1:
        return f"{first}-{parts[1].lower()}"
    return first


def render(result: Survey) -> str:
    lines: list[str] = ["# Estate survey", ""]

    def table(title: str, rows, headers) -> None:
        if title:
            lines.append(f"## {title}")
            lines.append("")
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|" + "|".join(["---"] * len(headers)) + "|")
        for row in rows:
            lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
        lines.append("")

    table("Devices by platform", result.by_platform, ["vendor", "devices"])
    table("Devices by location", result.by_location, ["location", "devices"])
    table("Devices by collector", result.by_collector, ["collector_id", "devices"])

    lines.append("## Repository layout")
    lines.append("")
    if result.location_is_usable:
        lines.append("`location` is populated and varied: use it for the site level "
                     "of the mirror path.")
    else:
        lines.append("`location` is unusable for grouping — most devices share one "
                     "value. The datacenter has to come from the hostname "
                     "convention instead (`datacenter_from_hostname`).")
        lines.append("")
        lines.append("How the fallback reads the hostnames actually present:")
        lines.append("")
        seen: dict[str, str] = {}
        for row in result.captures:
            dc = datacenter_from_hostname(row[0])
            if dc and dc not in seen:
                seen[dc] = row[0]
        table("", sorted((dc, host) for dc, host in seen.items()),
              ["datacenter", "example hostname"])
    lines.append("")

    lines.append("## Hostname collisions")
    lines.append("")
    if result.collisions:
        lines.append("Two devices under one name would share a directory in the "
                     "mirror, each overwriting the other on every run — with no "
                     "error, just a device that appears to change completely every "
                     "day. These need the datacenter or collector in the path:")
        lines.append("")
        table("", result.collisions,
              ["hostname", "count", "collectors", "locations"])
    else:
        lines.append("None. Hostname alone is currently unique — but these tenants "
                     "are organisations merging, so this can change with the next "
                     "onboarding. The path should not depend on it holding.")
        lines.append("")

    lines.append("## Captures too small to be configurations")
    lines.append("")
    suspicious = result.suspicious_captures
    if suspicious:
        lines.append(f"{len(suspicious)} device(s) store fewer than "
                     f"{SUSPICIOUS_CAPTURE_BYTES} bytes for a full configuration. "
                     "These report successful collection while holding an error "
                     "string or nothing — a collector-side finding:")
        lines.append("")
        table("", [(row[0], row[1], row[4], str(row[5])[:19]) for row in suspicious],
              ["hostname", "vendor", "bytes", "last capture"])
    else:
        lines.append("None.")
        lines.append("")

    return "\n".join(lines) + "\n"
