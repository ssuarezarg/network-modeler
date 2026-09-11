"""Stage 1 - read captured configurations from the collector database.

Read-only, against the **viewer** database. This pipeline runs in the viewer
environment and has no route to a collector's local database.

Accepted consequence, recorded here so it is not rediscovered later: the viewer
sync masks every credential with the constant literal `[OMITTED_BY_SANITIZER]`.
All secrets therefore collapse to one string, and **a rotated credential produces
no diff**. That signal is absent from the source data and cannot be recovered
downstream. If auditing credential rotation ever becomes a requirement, it needs
a second pipeline on the collector side.

Schema, as confirmed against the collector's SQLAlchemy models:

    raw_outputs(id UUID PK, execution_log_id UUID, device_id UUID,
                command TEXT, output TEXT, collected_at TIMESTAMPTZ)
    devices(id UUID PK, hostname, ip_address, vendor, os_version, device_type,
            serial_number, role, location, port, collector_id)

`raw_outputs` is append-only with full history and no retention policy: ~102k
rows for 15 devices over 4 months, growing without bound.

**Snapshot, not watermark, by default.** Rows reach the viewer through a periodic
sync, so a capture taken at T can arrive long after T. A watermark on
`collected_at` would permanently skip every row that lands late - which, with a
sync in the path, is the normal case rather than an edge case. So the default is
to take the current latest-per-device snapshot on each run and let content
hashing in Stage 5 decide what actually changed. At this estate size that costs
nothing, and it cannot silently lose a capture.

`fetch(since=...)` keeps the incremental path available for a much larger estate,
but it is only safe against a column that is monotonic *on arrival in the viewer*.
`collected_at` is not that column.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Command strings, taken from the live viewer database (2026-09-11) rather than
# assumed. The `SELECT command, count(*) ... GROUP BY command` output is what
# these are based on; four things in it changed the design:
#
#  * `show configuration` (Juniper) and `show config running` (Palo Alto) do NOT
#    appear at all. Those vendors are listed as supported by the collector but
#    have never actually been collected, so guessing their spellings would have
#    added dead code. `UNKNOWN_COMMANDS` is what surfaces them if they arrive.
#  * `show startup-config` IS collected (3331 rows). See STARTUP_CONFIG_COMMANDS.
#  * Firepower/FTD has no flat configuration command at all - see FTD_COMMANDS.
#  * `show interface` and `show interfaces` both exist; neither is a full config.

# The running configuration. This is what the mirror is built on.
RUNNING_CONFIG_COMMANDS: tuple[str, ...] = ("show running-config",)

# The startup configuration, also collected. Kept as a separate artifact because
# running-vs-startup divergence is a genuine operational finding: a device whose
# running config differs from its startup config silently reverts on reboot.
# Mirroring both makes that visible; see docs/ARCHITECTURE.md.
STARTUP_CONFIG_COMMANDS: tuple[str, ...] = ("show startup-config",)

# Firepower managed through FMC. There is no single command that returns a full
# configuration: the state is spread across several REST endpoints
# (device detail, interfaces, access policy, routes, NAT), each stored as its own
# row and almost certainly JSON rather than CLI text.
#
# Deliberately NOT part of P1. Mirroring these means deciding how to compose five
# endpoints into one artifact and how to normalise JSON for diffing - a different
# problem from mirroring CLI text, and one that deserves its own decision rather
# than being bolted on. FTD devices are reported as unsupported instead of being
# silently absent.
FTD_COMMANDS: tuple[str, ...] = (
    "fmc_device_detail", "fmc_interfaces", "fmc_acp", "fmc_routes",
    "fmc_nat", "fmc_version", "fmc_devices",
)

def all_config_commands(*, include_startup: bool = False) -> list[str]:
    commands = list(RUNNING_CONFIG_COMMANDS)
    if include_startup:
        commands += [c for c in STARTUP_CONFIG_COMMANDS if c not in commands]
    return commands


# Latest capture per (device, command). DISTINCT ON is Postgres-specific and
# rides the (device_id, command, collected_at) index directly.
LATEST_PER_DEVICE = """
SELECT DISTINCT ON (r.device_id, r.command)
       r.id, r.device_id, r.command, r.output, r.collected_at,
       d.hostname, d.vendor, d.os_version, d.device_type,
       d.serial_number, d.role, d.location, d.collector_id
  FROM raw_outputs r
  JOIN devices d ON d.id = r.device_id
 WHERE r.command = ANY(%(commands)s)
   AND (%(collector_id)s IS NULL OR d.collector_id = %(collector_id)s)
 ORDER BY r.device_id, r.command, r.collected_at DESC
"""

# Incremental pull. See `watermark_with_overlap()` for why the caller should
# subtract a margin before passing `since`.
SINCE_WATERMARK = """
SELECT r.id, r.device_id, r.command, r.output, r.collected_at,
       d.hostname, d.vendor, d.os_version, d.device_type,
       d.serial_number, d.role, d.location, d.collector_id
  FROM raw_outputs r
  JOIN devices d ON d.id = r.device_id
 WHERE r.command = ANY(%(commands)s)
   AND r.collected_at > %(since)s
   AND (%(collector_id)s IS NULL OR d.collector_id = %(collector_id)s)
 ORDER BY r.device_id, r.command, r.collected_at DESC
"""

# One device by hostname. Matched case-insensitively: hostnames are entered by
# people and `CORE-RTR-01` should find `core-rtr-01`. The devices table is
# tiny, so losing the index to lower() costs nothing.
LATEST_BY_HOSTNAME = """
SELECT DISTINCT ON (r.device_id)
       r.id, r.device_id, r.command, r.output, r.collected_at,
       d.hostname, d.vendor, d.os_version, d.device_type,
       d.serial_number, d.role, d.location, d.collector_id
  FROM raw_outputs r
  JOIN devices d ON d.id = r.device_id
 WHERE lower(d.hostname) = lower(%(hostname)s)
   AND r.command = ANY(%(commands)s)
   AND (%(collector_id)s IS NULL OR d.collector_id = %(collector_id)s)
 ORDER BY r.device_id, r.collected_at DESC
"""

# Does the device exist at all? Asked separately so "no such device" and "device
# exists but has never had a configuration captured" are different messages.
# They are different problems with different fixes, and collapsing them into one
# "not found" sends people looking in the wrong place.
DEVICE_EXISTS = """
SELECT d.id, d.hostname, d.vendor, d.collector_id
  FROM devices d
 WHERE lower(d.hostname) = lower(%(hostname)s)
"""

# Suggestions when a hostname does not match, so a typo does not look like a
# missing device.
SIMILAR_HOSTNAMES = """
SELECT d.hostname, d.collector_id
  FROM devices d
 WHERE d.hostname IS NOT NULL
   AND lower(d.hostname) LIKE lower(%(fragment)s)
 ORDER BY d.hostname
 LIMIT 20
"""

# Commands that look like they return a whole configuration but that this module
# does not handle. Run it periodically: a new vendor onboarded to the collector
# would otherwise be missing from the mirror with no error anywhere.
#
# The filter matters. The database holds ~60 distinct commands, nearly all of them
# operational state (`show ip route`, `show cdp neighbors detail`, per-VRF BGP
# summaries). Reporting all of those as "unknown" would bury the one line that
# actually matters - a real Juniper or Palo Alto config command showing up.
UNKNOWN_COMMANDS = """
SELECT r.command, count(*) AS n, max(r.collected_at) AS last_seen
  FROM raw_outputs r
 WHERE r.command <> ALL(%(commands)s)
   AND (r.command ILIKE '%%config%%' OR r.command ILIKE '%%configuration%%')
 GROUP BY r.command
 ORDER BY n DESC
"""

# Only needed if the incremental path is ever adopted. The default snapshot
# query rides the existing (device_id, command, collected_at) index correctly,
# so no new index is required today.
#
# It would be needed then because that existing index leads with device_id: a
# query filtered only on collected_at cannot range-scan it and degrades to
# walking every index entry, on a table that grows without bound.
SUGGESTED_INDEX_IF_INCREMENTAL = (
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_raw_outputs_command_collected "
    "ON raw_outputs (command, collected_at);"
)


@dataclass(frozen=True)
class CapturedConfig:
    """One configuration capture plus everything needed to cite its origin."""

    row_id: str
    device_id: str
    command: str
    output: str
    collected_at: datetime
    hostname: str | None
    vendor: str | None
    os_version: str | None
    device_type: str | None
    serial_number: str | None
    role: str | None
    location: str | None
    collector_id: str | None

    @property
    def device_key(self) -> str:
        """Directory name for this device in the mirror.

        Hostname is used because a diff of `inventory/lac1/asr1006-r1/` is
        readable and a diff of a UUID path is not. Hostname is nullable and can
        change, so `device_id` is the real identity and is always recorded in
        meta.yaml: a rename is then detectable (same device_id, new hostname)
        and handled with `git mv`, which preserves history instead of showing
        the device being deleted and re-added.
        """
        if self.hostname:
            return slugify(self.hostname)
        return f"device-{self.device_id}"

    @property
    def site_key(self) -> str:
        """`location` is free text with no normalised catalogue behind it, so
        this is a best effort and collisions are possible. A site mapping file
        should override it once the real values are known."""
        return slugify(self.location) if self.location else "unassigned"


# Characters that become a single "-". The hyphen itself belongs here: network
# hostnames are full of them, and dropping them both mangles the path and can
# collide two distinct devices onto one directory.
_SEPARATORS = set(" -_./\\:")


def slugify(value: str) -> str:
    out: list[str] = []
    for char in value.strip().lower():
        if char.isalnum():
            out.append(char)
        elif char in _SEPARATORS and out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-") or "unnamed"


def watermark_with_overlap(last_run: datetime, overlap: timedelta = timedelta(hours=1)) -> datetime:
    """Step the watermark back before querying.

    Collection runs take time and `collected_at` defaults to the insert moment,
    so rows can land slightly out of order relative to a previous run's maximum.
    A strict `>` watermark would skip those permanently - a silently missing
    capture, the worst failure this pipeline has.

    Re-reading an overlap window is free: unchanged content is detected by hash
    in Stage 5 and produces no commit.
    """
    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=timezone.utc)
    return last_run - overlap


def fetch(
    connection,
    *,
    collector_id: str | None = None,
    since: datetime | None = None,
) -> list[CapturedConfig]:
    """Return captures. `connection` is a DB-API connection (psycopg), passed in
    rather than opened here so this stays testable and connection policy lives
    with the caller.

    `collector_id` scopes the pull to one tenant. The viewer database is
    multi-tenant, so leaving this unset mirrors every customer it holds into one
    repository - almost never what is wanted, and not something to discover after
    the first push.

    `since` switches to the incremental path. Read the module docstring first:
    `collected_at` is not monotonic on arrival in the viewer, so a watermark over
    it can skip captures permanently.
    """
    commands = all_config_commands()
    params = {"commands": commands, "collector_id": collector_id}
    if since is None:
        sql = LATEST_PER_DEVICE
    else:
        sql = SINCE_WATERMARK
        params["since"] = since

    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        columns = [column[0] for column in cursor.description]
        return [CapturedConfig(**_row_to_kwargs(columns, row)) for row in cursor.fetchall()]


def find_unknown_commands(connection) -> list[tuple[str, int, datetime]]:
    with connection.cursor() as cursor:
        cursor.execute(UNKNOWN_COMMANDS, {"commands": all_config_commands()})
        return cursor.fetchall()


_COLUMN_TO_FIELD = {"id": "row_id"}


def _row_to_kwargs(columns: list[str], row: tuple) -> dict:
    kwargs = {}
    for column, value in zip(columns, row):
        field = _COLUMN_TO_FIELD.get(column, column)
        kwargs[field] = str(value) if field in ("row_id", "device_id") else value
    return kwargs


class DeviceNotFound(LookupError):
    """No device with that hostname."""


class NoConfigCaptured(LookupError):
    """The device exists but has no configuration capture."""


class AmbiguousDevice(LookupError):
    """More than one device matches - the viewer is multi-tenant."""


def connect(dsn: str | None = None):
    """Open a READ-ONLY connection to the viewer database.

    psycopg is imported here rather than at module scope so every other part of
    this package stays importable and testable without a database driver
    installed.

    The session is forced read-only at the server. The role should already be
    SELECT-only, but this pipeline has no business writing under any
    circumstance, and a guarantee that does not depend on the grants being
    correct is worth the one extra statement.
    """
    try:
        import psycopg  # type: ignore
    except ImportError:  # pragma: no cover - environment dependent
        try:
            import psycopg2 as psycopg  # type: ignore
        except ImportError:
            raise SystemExit(
                "psycopg is not installed. Install it with:\n"
                "  pip install 'psycopg[binary]'\n"
                "Connection settings come from the standard libpq environment "
                "variables (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD) "
                "or from --dsn."
            )

    try:
        connection = psycopg.connect(dsn) if dsn else psycopg.connect()
    except psycopg.OperationalError as error:
        raise SystemExit(_connection_help(dsn, error)) from None

    with connection.cursor() as cursor:
        cursor.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
    return connection


def _connection_help(dsn: str | None, error: Exception) -> str:
    """Turn a libpq connection failure into something actionable.

    Worth the effort for one case in particular: with no settings at all, libpq
    silently defaults to a local Unix socket and the resulting error talks about
    a missing socket file rather than about the configuration nobody supplied.
    That sends people looking for a Postgres server on the wrong machine.
    """
    configured = [name for name in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER")
                  if os.environ.get(name)]

    lines = [f"Could not connect to the database: {error}".rstrip(), ""]

    if not dsn and not configured:
        lines += [
            "No connection settings were given, so libpq fell back to a local Unix",
            "socket - which is why the error mentions a socket file rather than a",
            "host. Set the standard variables (they keep the password off the",
            "command line, where ps and shell history would see it):",
            "",
            "    export PGHOST=127.0.0.1 PGPORT=5432",
            "    export PGDATABASE=netcollector PGUSER=extractor_ro",
            "    export PGPASSWORD=...",
            "",
            "If the viewer's Postgres runs in Docker, find it with:",
            "",
            "    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'",
            "",
            "A container showing 0.0.0.0:5432->5432/tcp is reachable at PGHOST=127.0.0.1.",
            "One showing only 5432/tcp publishes no port to the host; connect over the",
            "compose network instead, or read its settings with:",
            "",
            "    docker inspect <container> --format '{{range .Config.Env}}{{println .}}{{end}}'",
        ]
    else:
        shown = ", ".join(f"{n}={os.environ[n]}" for n in configured) or f"--dsn {dsn!r}"
        lines += [f"Using: {shown}", "",
                  "Check the host and port are reachable from this machine, that the",
                  "database name is right, and that the role may connect."]

    return "\n".join(lines)


def fetch_by_hostname(
    connection,
    hostname: str,
    *,
    collector_id: str | None = None,
) -> CapturedConfig:
    """Return the most recent running-config capture for one device.

    Raises DeviceNotFound, NoConfigCaptured or AmbiguousDevice - each a distinct
    situation that needs a distinct response from whoever ran the command.
    """
    params = {
        "hostname": hostname,
        "commands": all_config_commands(),
        "collector_id": collector_id,
    }

    with connection.cursor() as cursor:
        cursor.execute(LATEST_BY_HOSTNAME, params)
        columns = [column[0] for column in cursor.description]
        rows = cursor.fetchall()

    if len(rows) > 1:
        # The viewer holds several tenants; the same hostname can legitimately
        # exist in more than one of them.
        collectors = sorted({str(row[columns.index("collector_id")]) for row in rows})
        raise AmbiguousDevice(
            f"{len(rows)} devices named {hostname!r} across collectors: "
            f"{', '.join(collectors)}. Narrow it with --collector-id."
        )

    if rows:
        return CapturedConfig(**_row_to_kwargs(columns, rows[0]))

    with connection.cursor() as cursor:
        cursor.execute(DEVICE_EXISTS, {"hostname": hostname})
        existing = cursor.fetchall()

    if existing:
        raise NoConfigCaptured(
            f"Device {hostname!r} exists but has no capture of "
            f"{' or '.join(all_config_commands())}. It may be a platform whose "
            f"configuration is collected differently (Firepower/FTD arrives as "
            f"fmc_* endpoints, not a flat config)."
        )

    raise DeviceNotFound(f"No device named {hostname!r}.")


def similar_hostnames(connection, hostname: str) -> list[tuple[str, str]]:
    fragment = f"%{hostname.strip('%')}%"
    with connection.cursor() as cursor:
        cursor.execute(SIMILAR_HOSTNAMES, {"fragment": fragment})
        return list(cursor.fetchall())
