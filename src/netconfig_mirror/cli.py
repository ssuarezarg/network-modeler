"""Model one device's configuration.

    netconfig-mirror device <hostname>        # look it up in the viewer database
    netconfig-mirror file   <config-file>     # model a config from disk

Both paths run the same pipeline - normalise, redact, detect, parse, render -
and write `device.yaml`, `raw.cfg` and `meta.yaml` per device. Output goes to
local disk; committing to Git is a later stage.

Database settings come from the standard libpq environment variables
(PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD) or from --dsn, so credentials
never need to appear on a command line where `ps` and shell history can see them.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import batch as batchlib
from . import analysis, envfile, extract, gitops, inventory, jsondoc, layout
from .blocks import ConfigDocument
from .detect import detect
from . import freshness as freshnesslib
from .freshness import DEFAULT_STALE_AFTER
from .model import DeviceModel
from .normalize import normalize
from .parsers import ios, nxos
from .redact import RedactionError, redact_or_raise

PARSERS = {"ios": ios, "iosxe": ios, "nxos": nxos}
KEY_ENV = "NETCONFIG_MIRROR_HMAC_KEY"

EXIT_OK = 0
EXIT_REDACTION_REFUSED = 2
EXIT_NO_PARSER = 3
EXIT_NOT_FOUND = 4
# Batch completed, but something needs a person to look at it.
EXIT_BATCH_ATTENTION = 5
# The repository could not be used as given.
EXIT_REPO = 6
# A device named on the command line is not in the mirror.
EXIT_NO_DEVICE = 7


def load_key(key_file: str | None) -> bytes:
    """The HMAC key, from a file or the environment.

    Deliberately has no default. A built-in fallback would make every token
    reproducible by anyone holding the source, which is the one property the key
    exists to provide.
    """
    if key_file:
        return Path(key_file).read_bytes().strip()
    value = os.environ.get(KEY_ENV)
    if value:
        return value.encode()
    raise SystemExit(
        f"No HMAC key. Set {KEY_ENV} or pass --key-file.\n"
        "  openssl rand -hex 32 > ~/.netconfig-mirror.key\n"
        "Keep it outside the mirror repository, and back it up: losing it changes "
        "every redaction token at once, producing a spurious diff on every device."
    )


def build_model(config_text: str, key: bytes, *, hint_platform=None, hint_version=None):
    clean, provenance = normalize(config_text)
    redacted, redaction = redact_or_raise(clean, key)
    detection = detect(redacted, hint_platform=hint_platform, hint_version=hint_version)

    parser = PARSERS.get(detection.platform)
    if parser is None:
        return None, ConfigDocument(redacted), detection, provenance, redaction, redacted

    model, doc = parser.parse(
        redacted, platform=detection.platform, os_version=detection.os_version)
    return model, doc, detection, provenance, redaction, redacted


def write_outputs(out_root: Path, name: str, model: DeviceModel, doc, detection,
                  provenance, redaction, redacted: str, capture=None) -> Path:
    out_dir = (out_root / name) if name != "." else out_root
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "device.yaml").write_text(
        yaml.safe_dump(model.to_dict(), sort_keys=False, default_flow_style=False,
                       allow_unicode=True, width=100),
        encoding="utf-8")
    (out_dir / "raw.cfg").write_text(redacted, encoding="utf-8")

    meta = _meta(detection, doc, provenance, redaction, capture)
    (out_dir / "meta.yaml").write_text(
        yaml.safe_dump(meta, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return out_dir


def _meta(detection, doc, provenance, redaction, capture) -> dict:
    meta = {
        "platform": detection.platform,
        "os_version": detection.os_version,
        "detection_confidence": detection.confidence,
        "detection_source": detection.source,
        "coverage": {
            "modelled_lines": doc.consumed_lines,
            "significant_lines": doc.significant_lines,
            "modelled_pct": round(doc.coverage() * 100, 1),
            "accounted_pct": round(doc.accounted() * 100, 1),
        },
        "redaction": {
            "tokens_written": redaction.total,
            "upstream_sanitised": redaction.upstream_sanitised,
        },
        "provenance": provenance.as_dict(),
    }
    if capture is not None:
        # Source citation. `row_id` is stable across viewer syncs because the
        # merge restores a pg_dump with the original column values rather than
        # regenerating identifiers.
        meta["source"] = {
            "row_id": capture.row_id,
            "device_id": capture.device_id,
            "command": capture.command,
            "collected_at": capture.collected_at.isoformat(),
            "collector_id": capture.collector_id,
            "location": capture.location,
        }
    return meta


def report(doc, detection, redaction, show_unmodelled: int, capture=None) -> None:
    out = sys.stderr
    print(f"\nplatform     : {detection.platform} ({detection.confidence} confidence, "
          f"from {detection.source}) {detection.os_version or ''}", file=out)

    if capture is not None:
        age = datetime.now(timezone.utc) - capture.collected_at
        stale = " ** STALE **" if age > DEFAULT_STALE_AFTER else ""
        print(f"captured     : {capture.collected_at.isoformat()} "
              f"({age.days}d ago){stale}", file=out)

    print(f"significant  : {doc.significant_lines} lines", file=out)
    print(f"modelled     : {doc.consumed_lines} ({doc.coverage() * 100:.1f}%)", file=out)
    print(f"accounted    : {doc.accounted() * 100:.1f}% (modelled + recognised)", file=out)
    print(f"redaction    : {redaction.total} token(s), "
          f"{redaction.upstream_sanitised} already masked upstream", file=out)

    remaining = doc.unconsumed()
    if remaining:
        print(f"\nunrecognised : {len(remaining)} lines. Most common:", file=out)
        for prefix, count in doc.unconsumed_summary(show_unmodelled):
            print(f"  {count:>4}x  {prefix}", file=out)


def _finish(args, config_text, key, capture=None, name_fallback="device") -> int:
    try:
        model, doc, detection, provenance, redaction, redacted = build_model(
            config_text, key,
            hint_platform=args.platform,
            hint_version=getattr(capture, "os_version", None) if capture else None,
        )
    except RedactionError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        print("A credential line came out unredacted. Since the viewer sanitises "
              "upstream, this most likely means its sanitiser has a gap - worth "
              "reporting there, not only fixing here.", file=sys.stderr)
        return EXIT_REDACTION_REFUSED

    if model is None:
        name = (capture.device_key if capture else None) or name_fallback
        out_dir = _write_unparsed(Path(args.out), name, detection, provenance,
                                  redaction, redacted, capture)
        _explain_no_parser(detection, redacted, out_dir)
        return EXIT_NO_PARSER

    name = (capture.device_key if capture else None) or model.device.hostname or name_fallback
    out_dir = write_outputs(Path(args.out), name, model, doc, detection,
                            provenance, redaction, redacted, capture)
    print(f"wrote {out_dir}/device.yaml")
    report(doc, detection, redaction, args.show_unmodelled, capture)
    return EXIT_OK


def _write_unparsed(out_root: Path, name: str, detection, provenance, redaction,
                    redacted: str, capture) -> Path:
    """Save the capture even though it could not be modelled.

    Throwing the fetch away on a detection failure leaves nobody able to see
    what actually came back, which is the one thing needed to fix it.
    """
    out_dir = out_root / name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "raw.cfg").write_text(redacted, encoding="utf-8")
    (out_dir / "meta.yaml").write_text(yaml.safe_dump({
        "status": "unparsed",
        "platform": detection.platform,
        "detection_confidence": detection.confidence,
        "detection_scores": detection.scores,
        "os_version": detection.os_version,
        "redaction": {"tokens_written": redaction.total,
                      "upstream_sanitised": redaction.upstream_sanitised},
        "provenance": provenance.as_dict(),
        "source": ({"row_id": capture.row_id, "command": capture.command,
                    "collected_at": capture.collected_at.isoformat(),
                    "vendor": capture.vendor, "os_version": capture.os_version}
                   if capture else None),
    }, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return out_dir


def _explain_no_parser(detection, redacted: str, out_dir: Path) -> None:
    out = sys.stderr
    print(f"No parser for platform '{detection.platform}' "
          f"({detection.confidence} confidence).", file=out)
    print("Supported today: ios, iosxe. ASA, NX-OS and IOS-XR need their own "
          "parsers.", file=out)

    if detection.scores:
        ranked = ", ".join(f"{name}={score}" for name, score in
                           sorted(detection.scores.items(), key=lambda kv: -kv[1]))
        print(f"\nDetection scores : {ranked}", file=out)
    else:
        # Zero markers is a different situation from "an unsupported platform".
        # It usually means the stored text is not a flat CLI configuration at
        # all: a collector error message, a JSON payload, or an empty capture.
        print("\nNo platform marker matched at all. That is usually not an "
              "unsupported\nplatform - it more often means the stored output is "
              "not a CLI configuration:\nan error string the collector saved, a "
              "JSON payload, or an empty capture.", file=out)

    lines = redacted.split("\n")
    print(f"\nCapture is {len(redacted)} bytes, {len(lines)} lines. "
          f"First 15, redacted:", file=out)
    print("-" * 68, file=out)
    for line in lines[:15]:
        print(f"  {line[:100]}", file=out)
    print("-" * 68, file=out)

    # What the first fifteen lines cannot tell you is how big each part of the
    # configuration is, and that is what decides the scope of the parser that
    # has to be written next. Scoping it from a sample of the top of the file
    # means writing for whatever happens to appear first.
    census = ConfigDocument(redacted).command_census()
    if census:
        print("\nCommand census - what a parser for this platform would have "
              "to cover:", file=out)
        print(f"  {'blocks':>7}  {'nested':>7}   command", file=out)
        for label, count, nested in census:
            print(f"  {count:>7}  {nested:>7}   {label}", file=out)

    print(f"\nFull redacted capture saved to {out_dir}/raw.cfg", file=out)


def cmd_device(args: argparse.Namespace) -> int:
    key = load_key(args.key_file)
    connection = extract.connect(args.dsn)
    try:
        try:
            capture = extract.fetch_by_hostname(
                connection, args.hostname, collector_id=args.collector_id)
        except extract.DeviceNotFound as error:
            print(str(error), file=sys.stderr)
            matches = extract.similar_hostnames(connection, args.hostname)
            if matches:
                print("\nDid you mean:", file=sys.stderr)
                for hostname, collector in matches:
                    print(f"  {hostname}  (collector: {collector})", file=sys.stderr)
            return EXIT_NOT_FOUND
        except (extract.NoConfigCaptured, extract.AmbiguousDevice) as error:
            print(str(error), file=sys.stderr)
            return EXIT_NOT_FOUND
    finally:
        pass

    try:
        return _finish(args, capture.output, key, capture=capture)
    finally:
        connection.close()


def cmd_batch(args: argparse.Namespace) -> int:
    key = load_key(args.key_file)
    connection = extract.connect(args.dsn)
    try:
        captures = extract.fetch(connection, collector_id=args.collector_id)
    finally:
        connection.close()

    # Collisions are computed over the WHOLE estate, not over the filtered
    # subset: a name that clashes must land in the same directory whether the
    # run covered one site or all of them, or a filtered run would quietly
    # write to a different path than a full one.
    collisions = layout.find_collisions(captures)

    selected = [c for c in captures if _matches(c, args)]
    report = batchlib.BatchReport(
        skipped_filtered=len(captures) - len(selected),
        acknowledged=batchlib.load_acknowledged(args.ack_file) if args.ack_file else set())

    for capture in sorted(selected, key=lambda c: (layout.site_of(c), c.device_key)):
        report.results.append(_model_one(capture, key, args, collisions))

    print(batchlib.render_summary(report))
    return EXIT_BATCH_ATTENTION if report.needs_attention else EXIT_OK


def _matches(capture, args) -> bool:
    if args.site and layout.site_of(capture) != extract.slugify(args.site):
        return False
    if args.vendor and (capture.vendor or "") != args.vendor:
        return False
    return True


def _model_one(capture, key: bytes, args, collisions) -> "batchlib.DeviceResult":
    site = layout.site_of(capture)
    result = batchlib.DeviceResult(
        hostname=capture.label,
        site=site,
        outcome=batchlib.OK,
        device_id=capture.device_id,
        collected_at=capture.collected_at,
    )

    attempt, detail, outcome = batchlib.should_attempt(capture)
    if not attempt:
        result.outcome, result.detail = outcome, detail
        return result

    try:
        model, doc, detection, provenance, redaction, redacted = build_model(
            capture.output, key, hint_platform=args.platform,
            hint_version=capture.os_version)
    except RedactionError as error:
        result.outcome, result.detail = batchlib.REDACTION_REFUSED, str(error)
        return result
    except Exception as error:  # noqa: BLE001 - one device must not stop the run
        result.outcome, result.detail = batchlib.ERROR, f"{type(error).__name__}: {error}"
        return result

    result.platform = detection.platform
    if model is None:
        result.outcome = batchlib.NO_PARSER
        result.detail = f"platform {detection.platform}"
        return result

    relative = layout.device_path(capture, collisions)
    out_dir = write_outputs(Path(args.out) / relative, ".", model, doc, detection,
                            provenance, redaction, redacted, capture)
    result.path = relative
    result.modelled_pct = round(doc.coverage() * 100, 1)
    result.accounted_pct = round(doc.accounted() * 100, 1)
    # Print the path actually written, not a reconstruction of it. Showing
    # `site/hostname` hid the collision suffix, so two colliding devices printed
    # as two identical lines - indistinguishable from the silent overwrite this
    # whole mechanism exists to prevent.
    shown = relative[len(layout.ROOT) + 1:]
    print(f"  {shown:<34} {detection.platform:<6} "
          f"{result.modelled_pct:>5.1f}% modelled")
    return result


def cmd_sync(args: argparse.Namespace) -> int:
    """Model the estate and commit the result to the mirror repository."""
    key = load_key(args.key_file)
    repo = gitops.MirrorRepo(args.repo)

    try:
        repo.ensure_ready()
    except gitops.GitError as error:
        print(str(error), file=sys.stderr)
        return EXIT_REPO

    connection = extract.connect(args.dsn)
    try:
        captures = extract.fetch(connection, collector_id=args.collector_id)
    finally:
        connection.close()

    collisions = layout.find_collisions(captures)
    selected = [c for c in captures if _matches(c, args)]
    complete_run = not (args.site or args.vendor or args.collector_id)

    repo.ensure_readme()
    existing = repo.existing_devices()
    sync = gitops.SyncReport()
    report = batchlib.BatchReport(
        skipped_filtered=len(captures) - len(selected),
        acknowledged=batchlib.load_acknowledged(args.ack_file) if args.ack_file else set())
    keep: set[str] = set()

    for capture in sorted(selected, key=lambda c: (layout.site_of(c), c.device_key)):
        relative = layout.device_path(capture, collisions)

        # Move before writing, so a renamed device keeps its history rather than
        # appearing as one deletion and one birth.
        previous = existing.get(capture.device_id)
        if previous and previous != relative and (repo.path / previous).is_dir():
            repo.move(previous, relative)
            sync.renamed.append((previous, relative))

        result = _sync_one(repo, capture, key, args, relative, sync)
        report.results.append(result)
        if result.outcome == batchlib.OK:
            keep.add(relative)

    # Firepower: several JSON endpoints per device, mirrored verbatim rather
    # than modelled. Skipped entirely on a filtered run that named a vendor,
    # since the filter was about CLI platforms.
    if not args.vendor:
        connection = extract.connect(args.dsn)
        try:
            composite = extract.fetch_composite(connection, collector_id=args.collector_id)
        finally:
            connection.close()

        mirrored: list[batchlib.DeviceResult] = []
        for captures in composite.values():
            first = captures[0]
            if not _matches(first, args):
                continue
            result = _sync_composite(repo, first, captures, key, sync)
            mirrored.append(result)
            if result.outcome == batchlib.MIRRORED:
                keep.add(result.path)

        # One device, two paths. Firepower has a `show running-config` row we
        # cannot parse as well as its FMC endpoints; keeping both results would
        # count it twice and report more devices than the estate contains.
        handled = {r.device_id for r in mirrored}
        report.results = [r for r in report.results if r.device_id not in handled]
        report.results += mirrored

    try:
        sync.removed = repo.prune(keep, complete_run=complete_run)
    except gitops.GitError as error:
        print(f"\n{error}", file=sys.stderr)
        return EXIT_REPO

    modelled = [r for r in report.results if r.outcome == batchlib.OK]
    # Every mirrored device, whichever path reached it. Leaving the JSON
    # platforms out would make them invisible to the one report that exists to
    # catch a device that stopped being collected — and FMC collection is
    # exactly the kind that stops quietly.
    fresh_inputs = [
        freshnesslib.Freshness(
            device_key=r.hostname,
            collected_at=r.collected_at,
            state=freshnesslib.STALE if r.is_stale else freshnesslib.FRESH)
        for r in report.results
        if r.collected_at is not None
        and r.outcome in (batchlib.OK, batchlib.MIRRORED)
    ]
    repo.write_report("freshness.md", freshnesslib.render_report(fresh_inputs))

    sites = sorted({r.site for r in modelled})
    commit = repo.commit(gitops.build_message(sync, sites=sites if not complete_run else None))
    sync.committed = commit

    print(batchlib.render_summary(report))
    if commit:
        print(f"\ncommitted {commit}: {len(sync.changed)} changed, "
              f"{len(sync.renamed)} renamed, {len(sync.removed)} removed")
    else:
        # The normal outcome on a network that did not change, and the point of
        # the whole exercise: silence means nothing moved.
        print("\nnothing changed; no commit")

    # Pushing is driven by "is the local branch ahead", not by "did this run
    # commit". A push that failed once would otherwise strand its commit
    # forever: the next run finds nothing new to commit, so it would never try
    # to push again, and the remote mirror silently stops advancing while every
    # run reports success.
    if args.push:
        try:
            if repo.push_needed():
                repo.push()
                sync.pushed = True
                print("pushed")
            else:
                print("remote already up to date")
        except gitops.GitError as error:
            print(f"\nCOMMITTED LOCALLY BUT NOT PUSHED: {error}", file=sys.stderr)
            print(f"The work is safe in {args.repo}; re-run once the remote is "
                  f"reachable, or push by hand.", file=sys.stderr)
            return EXIT_REPO

    return EXIT_BATCH_ATTENTION if report.needs_attention else EXIT_OK


def _sync_one(repo, capture, key: bytes, args, relative: str,
              sync: "gitops.SyncReport") -> "batchlib.DeviceResult":
    result = batchlib.DeviceResult(
        hostname=capture.label,
        site=layout.site_of(capture), outcome=batchlib.OK,
        device_id=capture.device_id, collected_at=capture.collected_at,
        path=relative)

    attempt, detail, outcome = batchlib.should_attempt(capture)
    if not attempt:
        result.outcome, result.detail = outcome, detail
        return result

    try:
        model, doc, detection, provenance, redaction, redacted = build_model(
            capture.output, key, hint_platform=args.platform,
            hint_version=capture.os_version)
    except RedactionError as error:
        result.outcome, result.detail = batchlib.REDACTION_REFUSED, str(error)
        return result
    except Exception as error:  # noqa: BLE001 - one device must not stop the run
        result.outcome, result.detail = batchlib.ERROR, f"{type(error).__name__}: {error}"
        return result

    result.platform = detection.platform
    if model is None:
        result.outcome, result.detail = batchlib.NO_PARSER, f"platform {detection.platform}"
        return result

    result.modelled_pct = round(doc.coverage() * 100, 1)
    result.accounted_pct = round(doc.accounted() * 100, 1)

    changed = repo.write_content(
        relative,
        yaml.safe_dump(model.to_dict(), sort_keys=False, default_flow_style=False,
                       allow_unicode=True, width=100),
        redacted)

    if changed:
        # Provenance is written only alongside a real change, so `collected_at`
        # reads as "when the configuration we hold was captured" rather than
        # "when we last looked" - and an unchanged device stays untouched.
        repo.write_meta(relative, yaml.safe_dump(
            _meta(detection, doc, provenance, redaction, capture),
            sort_keys=False, allow_unicode=True))
        sync.changed.append(relative)
        print(f"  changed  {relative[len(layout.ROOT) + 1:]}")

    sync.written.append(relative)
    return result


def cmd_compare(args: argparse.Namespace) -> int:
    """Two devices side by side, by the shape of the difference not its text."""
    devices = analysis.load_devices(args.repo)
    first = analysis.find_device(devices, args.device_a)
    second = analysis.find_device(devices, args.device_b)

    for name, found in ((args.device_a, first), (args.device_b, second)):
        if found is None:
            print(f"No device matching {name!r} in {args.repo}.", file=sys.stderr)
            close = [d.hostname for d in devices][:200]
            import difflib
            hint = difflib.get_close_matches(name, close, n=3, cutoff=0.5)
            if hint:
                print("Did you mean: " + ", ".join(hint), file=sys.stderr)
            return EXIT_NO_DEVICE

    print(analysis.render_comparison(first, second,
                                     analysis.compare_policy(first, second)))
    return EXIT_OK


def _write_report(path: str, content: str) -> int:
    """Write a report, explaining the one failure that is not obvious.

    The container runs read-only apart from its mounts, so an output path
    outside them fails with a bare `OSError: Read-only file system` naming only
    the file. Redirecting stdout costs nothing and always works, so say so.
    """
    try:
        Path(path).write_text(content, encoding="utf-8")
    except OSError as error:
        print(f"Could not write {path}: {error}", file=sys.stderr)
        print("\nInside the container only the mounted repository and /tmp are "
              "writable.\nEither write under one of those, or redirect instead:"
              "\n\n    docker/run.sh <command> > report.md\n", file=sys.stderr)
        return EXIT_REPO
    print(f"wrote {path}")
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    """Policy that cannot do what it appears to do, across the whole mirror."""
    devices = analysis.load_devices(args.repo)
    acknowledged = (batchlib.load_acknowledged(args.ack_file)
                    if args.ack_file else set())
    findings = analysis.audit(devices, acknowledged)
    if args.keys:
        # Keys only, one per line, for appending to the acknowledgement file.
        # Transcribing them by hand is how an acknowledgement silently stops
        # matching: one wrong character and the finding alerts again with
        # nothing to explain why.
        for finding in analysis.unacknowledged_dangling(findings):
            print(finding.key)
        return EXIT_OK

    report = analysis.render_audit(findings, devices, full=args.full)

    if args.out_file:
        written = _write_report(args.out_file, report)
        if written != EXIT_OK:
            return written
    else:
        print(report)

    # A dangling reference is a live misconfiguration, not an observation — but
    # only the ones nobody has taken responsibility for yet set the exit code.
    # Twenty-seven known findings would otherwise fail every scheduled run from
    # the first day, and a check that is always red is a check nobody reads.
    outstanding = analysis.unacknowledged_dangling(findings)
    if outstanding:
        print(f"\n{len(outstanding)} unacknowledged dangling reference(s). "
              f"Once raised, add their keys to the acknowledgement file:",
              file=sys.stderr)
        for finding in outstanding[:10]:
            print(f"  {finding.key}", file=sys.stderr)
        if len(outstanding) > 10:
            print(f"  ... and {len(outstanding) - 10} more", file=sys.stderr)
        return EXIT_BATCH_ATTENTION
    return EXIT_OK


def _sync_composite(repo, capture, captures, key: bytes,
                    sync: "gitops.SyncReport") -> "batchlib.DeviceResult":
    """Mirror one device whose configuration is several JSON endpoints."""
    relative = layout.device_path(capture)
    result = batchlib.DeviceResult(
        hostname=capture.label,
        site=layout.site_of(capture), outcome=batchlib.MIRRORED,
        platform="firepower", device_id=capture.device_id,
        collected_at=capture.collected_at, path=relative)

    rendered: dict[str, str] = {}
    for item in sorted(captures, key=lambda c: c.command):
        parsed = jsondoc.parse(item.output)
        if parsed is None:
            # Not JSON after all. Keep it verbatim rather than guessing — the
            # capture is still worth versioning, and the surprise is worth
            # seeing in the diff.
            rendered[f"{item.command}.txt"] = item.output
            continue

        parsed = jsondoc.strip_volatile(parsed)
        parsed, redaction = jsondoc.redact(parsed, key)
        residuals = jsondoc.audit_residuals(parsed)
        if residuals:
            result.outcome = batchlib.REDACTION_REFUSED
            result.detail = f"{len(residuals)} credential field(s): {residuals[:3]}"
            return result
        rendered[f"{item.command}.json"] = jsondoc.render(parsed)

    changed = repo.write_files(relative, rendered)
    if changed:
        repo.write_meta(relative, yaml.safe_dump({
            "platform": "firepower",
            "modelled": False,
            "note": "Mirrored as JSON endpoints. Firepower has no flat "
                    "configuration; this is L0 only.",
            "endpoints": sorted(rendered),
            "source": {"device_id": capture.device_id,
                       "collected_at": capture.collected_at.isoformat(),
                       "collector_id": capture.collector_id,
                       "location": capture.location},
        }, sort_keys=False, allow_unicode=True))
        sync.changed.append(relative)
        print(f"  changed  {relative[len(layout.ROOT) + 1:]}  (json)")

    return result


def cmd_volatile(args: argparse.Namespace) -> int:
    """Report which JSON fields move between two captures of one device.

    Run this before trusting the mirror for a JSON platform. Anything listed
    changes without anybody touching the device, and left in it produces a
    commit every night for a firewall that did not change.
    """
    connection = extract.connect(args.dsn)
    try:
        pairs = extract.fetch_recent_pairs(connection, args.hostname)
    finally:
        connection.close()

    if not pairs:
        print(f"No JSON captures for {args.hostname!r}.", file=sys.stderr)
        return EXIT_NOT_FOUND

    print(f"# Fields that moved between the two most recent captures — "
          f"{args.hostname}\n")
    total = 0
    for command, captures in sorted(pairs.items()):
        if len(captures) < 2:
            print(f"## {command}\n  only one capture; nothing to compare\n")
            continue

        newer, older = jsondoc.parse(captures[0][0]), jsondoc.parse(captures[1][0])
        if newer is None or older is None:
            print(f"## {command}\n  not JSON; compared as text — "
                  f"{'identical' if captures[0][0] == captures[1][0] else 'differs'}\n")
            continue

        moved = jsondoc.find_volatile(jsondoc.strip_volatile(older),
                                      jsondoc.strip_volatile(newer))
        print(f"## {command}   ({captures[1][1]:%Y-%m-%d %H:%M} -> "
              f"{captures[0][1]:%Y-%m-%d %H:%M})\n")
        if not moved:
            print("  nothing moved\n")
            continue
        total += len(moved)
        for path in moved[:args.limit]:
            print(f"  {path}")
        if len(moved) > args.limit:
            print(f"  ... and {len(moved) - args.limit} more")
        print()

    if total:
        print("Anything above that should NOT have changed belongs in the")
        print("volatile list, or every sync will commit this device again.")
    return EXIT_OK


def cmd_inventory(args: argparse.Namespace) -> int:
    """Survey the estate: platforms, sites, tenants, collisions, bad captures."""
    connection = extract.connect(args.dsn)
    try:
        survey = inventory.survey(connection)
    finally:
        connection.close()

    rendered = inventory.render(survey)
    if args.out_file:
        return _write_report(args.out_file, rendered)
    print(rendered)
    return EXIT_OK


def cmd_file(args: argparse.Namespace) -> int:
    key = load_key(args.key_file)
    path = Path(args.config)
    return _finish(args, path.read_text(encoding="utf-8", errors="replace"), key,
                   name_fallback=path.stem)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", default="./out", help="output directory (default: ./out)")
    parser.add_argument("--key-file", help=f"HMAC key file (or set {KEY_ENV})")
    parser.add_argument("--platform", help="override platform detection")
    parser.add_argument("--show-unmodelled", type=int, default=15,
                        help="how many unrecognised command prefixes to list")
    parser.add_argument("--ack-file", default=None,
                        help="file of hostnames whose failure is already known and "
                             "accepted; they no longer set the attention exit code")
    parser.add_argument("--env-file", default=None,
                        help="settings file to load (default: ./.env if present). "
                             "Real environment variables always win over it.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netconfig-mirror", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    device = sub.add_parser("device", help="model one device by hostname from the database")
    device.add_argument("hostname")
    device.add_argument("--dsn", help="libpq connection string (default: PG* env vars)")
    device.add_argument("--collector-id", help="disambiguate when a hostname exists "
                                               "in more than one tenant")
    _common(device)
    device.set_defaults(func=cmd_device)

    run = sub.add_parser("batch", help="model many devices: all, or one site/vendor")
    run.add_argument("--site", help="only this location (e.g. DC4, LD5)")
    run.add_argument("--vendor", help="only this devices.vendor value (e.g. cisco_nxos)")
    run.add_argument("--dsn", help="libpq connection string (default: PG* env vars)")
    run.add_argument("--collector-id", help="limit to one tenant")
    _common(run)
    run.set_defaults(func=cmd_batch)

    sync = sub.add_parser(
        "sync", help="model the estate and commit the result to the mirror repository")
    sync.add_argument("--repo", required=True,
                      help="path to the mirror repository working tree")
    sync.add_argument("--push", action="store_true", help="push after committing")
    sync.add_argument("--site", help="only this location")
    sync.add_argument("--vendor", help="only this devices.vendor value")
    sync.add_argument("--dsn", help="libpq connection string (default: PG* env vars)")
    sync.add_argument("--collector-id", help="limit to one tenant")
    _common(sync)
    sync.set_defaults(func=cmd_sync)

    volatile = sub.add_parser(
        "volatile", help="show which JSON fields move between two captures of a device")
    volatile.add_argument("hostname")
    volatile.add_argument("--dsn", help="libpq connection string (default: PG* env vars)")
    volatile.add_argument("--limit", type=int, default=25,
                          help="how many differing paths to list per endpoint")
    volatile.add_argument("--env-file", default=None,
                          help="settings file to load (default: ./.env if present)")
    volatile.set_defaults(func=cmd_volatile)

    compare = sub.add_parser(
        "compare", help="compare the routing policy of two devices in the mirror")
    compare.add_argument("device_a")
    compare.add_argument("device_b")
    compare.add_argument("--repo", required=True, help="path to the mirror repository")
    compare.add_argument("--env-file", default=None, help=argparse.SUPPRESS)
    compare.set_defaults(func=cmd_compare)

    policy_audit = sub.add_parser(
        "audit", help="find routing policy that cannot do what it appears to do")
    policy_audit.add_argument("--repo", required=True, help="path to the mirror repository")
    policy_audit.add_argument("--out-file", help="write the report here instead of stdout")
    policy_audit.add_argument("--ack-file", default=None,
                              help="findings already raised; they stay in the report "
                                   "but stop setting the exit code")
    policy_audit.add_argument("--keys", action="store_true",
                              help="print the key of every unacknowledged finding, "
                                   "one per line, to append to the acknowledgement file")
    policy_audit.add_argument("--full", action="store_true",
                              help="list every unreferenced prefix-list instead of a sample")
    policy_audit.add_argument("--env-file", default=None, help=argparse.SUPPRESS)
    policy_audit.set_defaults(func=cmd_audit)

    survey = sub.add_parser(
        "inventory", help="survey the estate: platforms, sites, tenants, "
                          "hostname collisions, captures too small to be configs")
    survey.add_argument("--dsn", help="libpq connection string (default: PG* env vars)")
    survey.add_argument("--out-file", help="write the report here instead of stdout")
    survey.add_argument("--env-file", default=None,
                        help="settings file to load (default: ./.env if present)")
    survey.set_defaults(func=cmd_inventory)

    from_file = sub.add_parser("file", help="model a configuration file from disk")
    from_file.add_argument("config")
    _common(from_file)
    from_file.set_defaults(func=cmd_file)

    args = parser.parse_args(argv)
    # Loaded before anything reads the environment, and never over the top of
    # variables that are already set.
    envfile.load(getattr(args, "env_file", None))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
