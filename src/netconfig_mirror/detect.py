"""Platform and OS-version detection for captured device configurations.

Stage 2 of the pipeline. The result is the dispatch key for every parser, so a
wrong answer here silently routes a config to the wrong parser and corrupts the
model. Two design choices follow from that:

1. **Weighted scoring, not first-match-wins.** Every marker that fires is
   recorded. A close call between two platforms is reported as low confidence
   rather than resolved silently.

2. **Collector metadata wins.** If the source database already knows the
   platform or version, that beats anything inferred from config text. Text
   inference is the fallback, not the primary source.

Why this is not trivial, from the LAC1 sample: an ASR1006 runs IOS-XE but its
running-config says `version 15.5`, exactly like classic IOS. A detector keyed
on `version 16/17` (the common shortcut) labels every IOS-XE 3.x box as `ios`.
The discriminators that actually hold are platform-specific config commands.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# (regex, weight). Weights are deliberate: a marker that only ever appears on
# one platform scores high; one that is merely typical scores low.
_MARKERS: dict[str, list[tuple[re.Pattern[str], int]]] = {
    "asa": [
        (re.compile(r"^ASA Version ", re.M), 10),
        (re.compile(r"^: Saved", re.M), 6),
        (re.compile(r"^nameif ", re.M), 4),
        (re.compile(r"^access-group .* global", re.M), 3),
    ],
    "iosxr": [
        (re.compile(r"^!! IOS XR", re.M), 10),
        (re.compile(r"^RP/\d+/", re.M), 6),
        (re.compile(r"^interface \S+\n line-console", re.M), 2),
    ],
    "nxos": [
        (re.compile(r"^feature \w", re.M), 6),
        (re.compile(r"^vdc \w", re.M), 6),
        (re.compile(r"^hardware profile", re.M), 4),
        (re.compile(r"^boot nxos ", re.M), 6),
    ],
    "iosxe": [
        # ASR1000/ISR4000-family platform commands. These do not exist on
        # classic IOS and are what separate IOS-XE 3.x from IOS 15.x, since
        # both report `version 15.x`.
        # Observed as `no platform punt-keepalive disable-kernel-core`: the
        # negated form still proves the command exists, which only IOS-XE does.
        (re.compile(r"^(?:no )?platform punt-keepalive", re.M), 8),
        (re.compile(r"^subscriber templating", re.M), 6),
        (re.compile(r"^(?:no )?platform (console|shell|hardware)", re.M), 6),
        (re.compile(r"^license (boot level|udi)", re.M), 4),
        # IOS-XE 16+ renumbered to match the IOS-XE train directly.
        (re.compile(r"^version 1[6-9]\.", re.M), 7),
    ],
    "ios": [
        (re.compile(r"^version 1[2-5]\.", re.M), 3),
        (re.compile(r"^service timestamps", re.M), 1),
        (re.compile(r"^boot-start-marker", re.M), 1),
    ],
}

_VERSION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("asa", re.compile(r"^ASA Version (\S+)", re.M)),
    # Stop at the closing paren: `version 10.3(5) [Maintenance Release]` and
    # `version 10.6(1) Bios:version` both carry trailing text that is not part
    # of the version number.
    ("nxos", re.compile(r"^version (\d+\.\d+\([^)]*\))", re.M)),
    ("*", re.compile(r"^version (\d+\.\d+\S*)", re.M)),
]

# Below this margin between the top two platforms, the call is not trustworthy
# enough to dispatch a parser on without a human looking.
_CONFIDENT_MARGIN = 4


@dataclass
class Detection:
    platform: str
    os_version: str | None
    confidence: str  # "high" | "low" | "none"
    scores: dict[str, int] = field(default_factory=dict)
    markers: list[str] = field(default_factory=list)
    source: str = "config"  # "collector" when the database supplied the answer


def detect(
    config_text: str,
    *,
    hint_platform: str | None = None,
    hint_version: str | None = None,
) -> Detection:
    """Identify (platform, os_version) for one captured configuration.

    `hint_platform` / `hint_version` come from the collector database and take
    precedence: the collector talked to the device, we are reading a text file.
    """
    scores: dict[str, int] = {}
    markers: list[str] = []

    for platform, patterns in _MARKERS.items():
        total = 0
        for pattern, weight in patterns:
            if pattern.search(config_text):
                total += weight
                markers.append(f"{platform}:{pattern.pattern}")
        if total:
            scores[platform] = total

    if scores:
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        best, best_score = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else 0
        confidence = "high" if best_score - runner_up >= _CONFIDENT_MARGIN else "low"
    else:
        best, confidence = "unknown", "none"

    version = _extract_version(config_text, best)

    version = normalize_version(version)

    if hint_platform:
        # Keep the inferred scores in the record even when overridden: a
        # collector hint that contradicts the config is worth being able to see.
        return Detection(
            platform=hint_platform,
            os_version=normalize_version(hint_version) or version,
            confidence="high",
            scores=scores,
            markers=markers,
            source="collector",
        )

    return Detection(
        platform=best,
        os_version=normalize_version(hint_version) or version,
        confidence=confidence,
        scores=scores,
        markers=markers,
    )


def normalize_version(version: str | None) -> str | None:
    """Keep the version number, drop whatever the platform appended to it.

    Applied to the collector's `devices.os_version` as well as to anything
    parsed from the config: the database holds values like
    `10.3(5) [Maintenance Release]`, and the suffix would travel into the model
    and into any path built from it. The database's original value stays
    recorded under `source` in meta.yaml, so nothing is lost.
    """
    if not version:
        return None
    first = version.strip().split()[0] if version.strip() else ""
    return first or None


def _extract_version(config_text: str, platform: str) -> str | None:
    for scope, pattern in _VERSION_PATTERNS:
        if scope not in (platform, "*"):
            continue
        match = pattern.search(config_text)
        if match:
            return match.group(1).strip()
    return None
