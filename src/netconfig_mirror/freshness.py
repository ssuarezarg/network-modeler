"""Staleness detection - distinguishing "nothing changed" from "nothing arrived".

The viewer database keeps no history of its own. Each sync runs
`DELETE FROM devices WHERE collector_id = 'X'` and reinserts whatever the
collector currently holds, and syncs fire when a collection run finishes rather
than on a fixed schedule. So if a collector stops - decommissioned, scheduler
wedged, credentials expired, network path broken - its devices simply stay in
the viewer at their last known state, with nothing marking them as abandoned.

For a mirror whose entire output is a diff, that is the worst failure mode there
is: a device that stopped being collected produces no diff at all, which reads
exactly like a device that has not changed. The mirror reports calm at precisely
the moment it went blind.

`collected_at` survives the sync unmodified, so staleness is detectable. This
module turns it into something visible: a committed report where a device
crossing the threshold produces a diff of its own.

Note on the report format: it deliberately records the capture timestamp and the
state, never a computed age. "Last seen 38 hours ago" would change on every run
and churn the repository for every device forever - the exact noise problem this
project is built to avoid (see `normalize.py`).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# A device collected less often than this is treated as stale. Deliberately
# generous: the point is to catch a collector that has stopped, not to alarm on
# a single missed run.
DEFAULT_STALE_AFTER = timedelta(days=7)

FRESH = "fresh"
STALE = "stale"


@dataclass(frozen=True)
class Freshness:
    device_key: str
    collected_at: datetime
    state: str

    @property
    def is_stale(self) -> bool:
        return self.state == STALE


def assess(
    captures,
    *,
    now: datetime | None = None,
    stale_after: timedelta = DEFAULT_STALE_AFTER,
) -> list[Freshness]:
    """Classify each capture as fresh or stale, newest first."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    results = []
    for capture in captures:
        collected_at = capture.collected_at
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)
        state = STALE if (now - collected_at) > stale_after else FRESH
        results.append(Freshness(capture.device_key, collected_at, state))

    return sorted(results, key=lambda f: (f.state, f.device_key))


def render_report(freshness: list[Freshness], *, stale_after: timedelta = DEFAULT_STALE_AFTER) -> str:
    """Deterministic Markdown for `reports/freshness.md`.

    Contains no value that moves on its own. The only things that can change are
    a new capture timestamp or a state transition, so this file sits still until
    something real happens - and then the diff says exactly what.
    """
    stale = [f for f in freshness if f.is_stale]

    lines = [
        "# Capture freshness",
        "",
        f"Devices are marked stale after {stale_after.days} days without a capture.",
        "",
        "This file exists because a device that stopped being collected produces no",
        "diff of its own: its configuration simply stops changing, which is",
        "indistinguishable from a device that is genuinely stable.",
        "",
        f"**{len(stale)} stale / {len(freshness)} total**",
        "",
        "| Device | Last capture (UTC) | State |",
        "|---|---|---|",
    ]

    for item in freshness:
        stamp = item.collected_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")
        marker = "**stale**" if item.is_stale else "fresh"
        lines.append(f"| {item.device_key} | {stamp} | {marker} |")

    return "\n".join(lines) + "\n"
