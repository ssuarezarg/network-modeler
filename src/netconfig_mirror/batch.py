"""Model many devices in one run.

Built for cron, which shapes every decision here:

* **One failure must not cost the other 72.** Each device is attempted
  independently and its outcome recorded; nothing aborts the run.
* **Outcomes are distinguished, not merged.** "No parser for this platform",
  "the capture is too small to be a configuration" and "redaction refused this
  device" are three different problems needing three different people to act.
  Collapsing them into a failure count hides which.
* **The exit code says whether a human is needed.** Silence from cron has to
  mean success, so anything that needs attention has to be visible in the
  status, not only in the output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .extract import CapturedConfig
from .freshness import DEFAULT_STALE_AFTER
from .inventory import SUSPICIOUS_CAPTURE_BYTES

OK = "ok"
# Captured and versioned, but not modelled: Firepower arrives as JSON endpoints
# rather than a configuration. Counted apart from OK so it cannot quietly drag
# the coverage figures — there is no coverage to report for it.
MIRRORED = "mirrored (json, no model)"
TOO_SMALL = "capture too small"
NO_PARSER = "no parser"
REDACTION_REFUSED = "redaction refused"
ERROR = "error"

# Order in which outcomes are reported: worst first, because a redaction refusal
# is a credential exposure upstream and should not be read after a list of
# routine skips.
OUTCOME_ORDER = [REDACTION_REFUSED, ERROR, TOO_SMALL, NO_PARSER, MIRRORED, OK]


@dataclass
class DeviceResult:
    hostname: str
    site: str
    outcome: str
    platform: str | None = None
    detail: str | None = None
    modelled_pct: float | None = None
    accounted_pct: float | None = None
    collected_at: datetime | None = None
    path: str | None = None

    @property
    def is_stale(self) -> bool:
        if self.collected_at is None:
            return False
        collected = self.collected_at
        if collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - collected) > DEFAULT_STALE_AFTER


@dataclass
class BatchReport:
    results: list[DeviceResult] = field(default_factory=list)
    skipped_filtered: int = 0
    # Devices whose problem is already known and accepted upstream. They still
    # appear in the summary; they just stop claiming someone's attention.
    acknowledged: set[str] = field(default_factory=set)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
        return counts

    @property
    def needs_attention(self) -> bool:
        """Anything a person has to look at, that they have not already seen.

        Two exclusions, both there to keep the signal worth reacting to:

        `NO_PARSER` never counts. Firepower is a known and accepted gap, and
        failing every nightly run over 24 devices would train people to ignore
        the exit code - the one thing it must not do.

        Acknowledged devices do not count either. Two devices in this estate
        store 65-byte error strings instead of configurations, every single
        night; that is a real finding, but once it has been raised with whoever
        owns the collector, repeating it daily is noise. Acknowledging them
        keeps the alert meaning "something NEW is wrong" - and a device that
        starts failing differently still trips it, because the acknowledgement
        is per device, not blanket.
        """
        for result in self.results:
            if result.outcome in (REDACTION_REFUSED, ERROR, TOO_SMALL):
                if result.hostname not in self.acknowledged:
                    return True
        return False

    def coverage_by_platform(self) -> dict[str, tuple[int, float, float]]:
        grouped: dict[str, list[DeviceResult]] = {}
        for result in self.results:
            if result.outcome == OK and result.platform:
                grouped.setdefault(result.platform, []).append(result)
        return {
            platform: (
                len(items),
                sum(r.modelled_pct or 0 for r in items) / len(items),
                sum(r.accounted_pct or 0 for r in items) / len(items),
            )
            for platform, items in sorted(grouped.items())
        }


def should_attempt(capture: CapturedConfig) -> tuple[bool, str | None]:
    """Whether this capture is worth trying to model.

    A capture far too small to be a configuration is reported as its own
    outcome rather than being handed to the parser, where it would surface as
    'platform unknown' and read like an unsupported device instead of a
    collector fault.
    """
    if len(capture.output) < SUSPICIOUS_CAPTURE_BYTES:
        return False, f"{len(capture.output)} bytes"
    return True, None


def render_summary(report: BatchReport) -> str:
    counts = report.counts()
    total = len(report.results)
    lines = [f"\n{'=' * 66}", f"{total} device(s) attempted"]

    if report.skipped_filtered:
        lines.append(f"{report.skipped_filtered} skipped by filter")
    lines.append("")

    for outcome in OUTCOME_ORDER:
        if counts.get(outcome):
            lines.append(f"  {counts[outcome]:>4}  {outcome}")

    coverage = report.coverage_by_platform()
    if coverage:
        lines += ["", "Coverage by platform (mean):", "",
                  f"  {'platform':<10} {'devices':>8} {'modelled':>10} {'accounted':>11}"]
        for platform, (count, modelled, accounted) in coverage.items():
            lines.append(f"  {platform:<10} {count:>8} {modelled:>9.1f}% {accounted:>10.1f}%")

    stale = [r for r in report.results if r.is_stale]
    if stale:
        lines += ["", f"{len(stale)} device(s) not captured in over "
                      f"{DEFAULT_STALE_AFTER.days} days:"]
        for result in sorted(stale, key=lambda r: r.collected_at or datetime.min):
            age = (datetime.now(timezone.utc)
                   - result.collected_at.replace(tzinfo=result.collected_at.tzinfo
                                                 or timezone.utc)).days
            lines.append(f"  {result.hostname:<24} {age:>4}d")

    for outcome in (REDACTION_REFUSED, ERROR, TOO_SMALL):
        affected = [r for r in report.results if r.outcome == outcome]
        if affected:
            lines += ["", f"{outcome}:"]
            for result in affected:
                mark = "  (acknowledged)" if result.hostname in report.acknowledged else ""
                lines.append(f"  {result.hostname:<24} {result.detail or ''}{mark}")

    if counts.get(REDACTION_REFUSED):
        lines += ["",
                  "A redaction refusal means a credential came through unredacted.",
                  "The viewer sanitises upstream, so this is most likely a gap in",
                  "THAT sanitiser - worth reporting there, not only fixing here."]

    lines.append("=" * 66)
    return "\n".join(lines)


def load_acknowledged(path) -> set[str]:
    """Hostnames whose failure is already known, one per line.

    Comments and blanks are ignored. A missing file is not an error: the default
    is to acknowledge nothing, which is the safe direction - an unreadable
    suppression list must never silently suppress.
    """
    from pathlib import Path

    target = Path(path)
    if not target.is_file():
        return set()

    names = set()
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            names.add(line)
    return names
