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

from . import envfile, extract
from .blocks import ConfigDocument
from .detect import detect
from .freshness import DEFAULT_STALE_AFTER
from .model import DeviceModel
from .normalize import normalize
from .parsers import ios
from .redact import RedactionError, redact_or_raise

PARSERS = {"ios": ios, "iosxe": ios}
KEY_ENV = "NETCONFIG_MIRROR_HMAC_KEY"

EXIT_OK = 0
EXIT_REDACTION_REFUSED = 2
EXIT_NO_PARSER = 3
EXIT_NOT_FOUND = 4


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
    out_dir = out_root / name
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "device.yaml").write_text(
        yaml.safe_dump(model.to_dict(), sort_keys=False, default_flow_style=False,
                       allow_unicode=True, width=100),
        encoding="utf-8")
    (out_dir / "raw.cfg").write_text(redacted, encoding="utf-8")

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

    (out_dir / "meta.yaml").write_text(
        yaml.safe_dump(meta, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return out_dir


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
        print(f"No parser for platform '{detection.platform}' "
              f"({detection.confidence} confidence).", file=sys.stderr)
        print("Supported today: ios, iosxe. ASA, NX-OS and IOS-XR need their own "
              "parsers; reporting this rather than emitting an empty model that "
              "would look valid.", file=sys.stderr)
        return EXIT_NO_PARSER

    name = (capture.device_key if capture else None) or model.device.hostname or name_fallback
    out_dir = write_outputs(Path(args.out), name, model, doc, detection,
                            provenance, redaction, redacted, capture)
    print(f"wrote {out_dir}/device.yaml")
    report(doc, detection, redaction, args.show_unmodelled, capture)
    return EXIT_OK


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
