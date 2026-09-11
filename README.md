# netconfig-mirror

Turns router configurations stored in the collector's Postgres database into a
structured, schema-validated YAML model.

Design and rationale: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
GitLab deployment: [`infra/gitlab/README.md`](infra/gitlab/README.md).

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[db,dev]'
```

**Install the project, do not just install the requirements.** The package lives
under `src/`, so `python -m netconfig_mirror.cli` from a bare checkout fails with
`No module named 'netconfig_mirror'` — nothing has put `src/` on the path.
`pip install -e .` fixes that and provides the `netconfig-mirror` command.

The `db` extra pulls in `psycopg`, needed only by the `device` subcommand; `file`
runs with PyYAML alone. To skip it: `pip install -e '.[dev]'`.

## The HMAC key

Redaction replaces each secret with a token derived from an HMAC, so an unchanged
credential produces no diff and a changed one does — without the value ever being
written down. That requires a key:

```bash
openssl rand -hex 32 > ~/.netconfig-mirror.key
chmod 600 ~/.netconfig-mirror.key
export NETCONFIG_MIRROR_HMAC_KEY=$(cat ~/.netconfig-mirror.key)
```

**Keep it outside this repository and back it up.** Losing it changes every token
at once, which shows up as a spurious diff on every device simultaneously.

## Usage

By hostname, from the database:

```bash
cp .env.example .env && chmod 600 .env    # fill in host, database, credentials
netconfig-mirror device CORE-RTR-01 --out ./out
```

`.env` is read from the working directory (or `--env-file`), and is gitignored.
It uses the standard libpq variable names, so real environment variables — from
a shell export, systemd, or a container — always take precedence over the file.
That way one setting can be overridden for a single run, and a scheduled job's
configuration cannot be replaced by a stale `.env` someone left behind.

Credentials never go on the command line, where `ps` and shell history would see
them. `--dsn` is available for one-offs.

From a file, no database needed:

```bash
netconfig-mirror file ./configs/router.txt --out ./out
```

Each run writes `out/<hostname>/`:

| File | Contents |
|---|---|
| `device.yaml` | the structured model |
| `raw.cfg` | the redacted configuration, verbatim |
| `meta.yaml` | provenance, coverage figures, redaction counts |

## Reading the coverage output

```
modelled     : 545 (59.1%)
accounted    : 99.6% (modelled + recognised)
unrecognised : 4 lines
```

**modelled** is the share of configuration lines that produced content in the
model. **accounted** adds lines that are recognised but deliberately not modelled
(`service timestamps`, `spanning-tree`, `class-map`...). The two are kept apart on
purpose: counting recognition as modelling would push the figure to 99% and make
it meaningless.

**The gap between `accounted` and 100% is what nobody has looked at yet** — the
only number that says whether the parser is finished for a platform. The
`unrecognised` list is ordered by frequency, so the next extractor worth writing
is chosen from evidence.

## Platform support

| Platform | Status |
|---|---|
| IOS, IOS-XE | supported |
| ASA, NX-OS, IOS-XR | detected, no parser — reported as unsupported |
| Firepower / FTD | out of scope: arrives as `fmc_*` REST endpoints, not a flat config |

An unsupported platform is reported rather than producing an empty model that
would look valid.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | modelled successfully |
| 2 | redaction refused — a credential line came out unredacted |
| 3 | no parser for the detected platform |
| 4 | device not found, ambiguous, or never captured |

Code 2 is the one to take seriously. Since the viewer sanitises upstream, it
most likely means **that** sanitiser has a gap — a finding to report there, not
only to patch here.
