"""Where each device lives in the mirror.

    inventory/<site>/<device>/

`devices.location` drives the site level: it is populated and varied in this
estate (LD5, DC4, AM5, CLL, ...). `inventory.datacenter_from_hostname` is the
fallback for devices whose location is missing.

**Collisions are resolved by device_id, not by structure.** The tempting fix for
two devices sharing a name is to put the datacenter or the tenant in the path,
and it does not work: the one real collision here is two devices both called
`Kernel`, in the same site and the same collector. Nothing in the hierarchy
separates them. So a colliding name gets a short suffix derived from the stable
`device_id` instead - deterministic, and it keeps both devices rather than
letting one silently overwrite the other on every run.

Getting this wrong fails silently. Two devices sharing a directory produce no
error at all: each run rewrites the files with the other device's content, and
the mirror shows a device that appears to reconfigure itself completely every
day, forever.
"""
from __future__ import annotations

from collections import defaultdict

from .extract import CapturedConfig, slugify
from .inventory import datacenter_from_hostname

ROOT = "inventory"

# Enough device_id to separate colliding names without making the path unreadable.
# These are UUIDs, so eight hex characters is ample at any plausible estate size.
_SUFFIX_LENGTH = 8


def site_of(capture: CapturedConfig) -> str:
    if capture.location:
        return slugify(capture.location)
    guessed = datacenter_from_hostname(capture.hostname)
    return slugify(guessed) if guessed else "unassigned"


def find_collisions(captures: list[CapturedConfig]) -> set[tuple[str, str]]:
    """(site, device_key) pairs claimed by more than one device_id."""
    owners: dict[tuple[str, str], set[str]] = defaultdict(set)
    for capture in captures:
        owners[(site_of(capture), capture.device_key)].add(capture.device_id)
    return {key for key, ids in owners.items() if len(ids) > 1}


def device_path(capture: CapturedConfig,
                collisions: set[tuple[str, str]] | None = None) -> str:
    """Repository-relative directory for one device."""
    site = site_of(capture)
    name = capture.device_key

    if collisions and (site, name) in collisions:
        name = f"{name}-{capture.device_id[:_SUFFIX_LENGTH]}"

    return f"{ROOT}/{site}/{name}"
