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

Many devices at once:

```bash
netconfig-mirror batch --out ./out                 # every device
netconfig-mirror batch --site DC4 --out ./out      # one location
netconfig-mirror batch --vendor cisco_nxos --out ./out
```

One device failing never aborts the run. The summary separates the outcomes that
need different people to act — `redaction refused` is a credential exposure
upstream, `capture too small` is a collector fault, `no parser` is a known gap —
and reports mean coverage per platform plus any device that has stopped being
captured.

Commit the result to the mirror repository:

```bash
netconfig-mirror sync --repo /srv/network-mirror --push
netconfig-mirror sync --repo /srv/network-mirror --site DC4
```

A run where nothing changed produces **no commit** — that silence is the point.
Provenance (`meta.yaml`) is rewritten only beside a real content change, so the
capture timestamps that move every night do not manufacture a daily diff.

A renamed device is `git mv`d so its history follows it. Devices that left the
database are removed only on a complete run, and a run that would remove more
than 10% of the mirror refuses: a collector that stopped reporting looks exactly
like a mass decommissioning.

Survey the estate before deciding anything:

```bash
netconfig-mirror inventory
```

Reports devices by platform, location and tenant, hostname collisions, and
captures too small to be configurations.

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

## What the model covers

Device identity, interfaces, VRFs, VLANs, static routes, BGP (including
neighbours inside VRF address-families), OSPF, access-lists, **prefix-lists and
route-maps**, and management services. NX-OS adds the `feature` set, the VXLAN
NVE interface and the VLAN-to-VNI mapping.

Prefix-lists record `referenced_by`: the route-maps that match them. It is
computed, not parsed, and it is the reason modelling them earns its place — a
prefix-list nothing references announces nothing, however many entries it holds.
On one real router, nine of thirty were in exactly that state.

## Asking questions of the mirror

```bash
netconfig-mirror audit --repo ./mirror
netconfig-mirror compare dc4-edge-r1 dc4-edge-r2 --repo ./mirror
```

`audit` looks for routing policy that cannot do what it appears to do:

- **Route-maps matching a prefix-list that does not exist.** The one worth
  acting on. A route-map matching a mistyped name does not fail — it matches
  nothing, so the policy the engineer believed they applied was never applied,
  and nothing anywhere reports it. Exits 5 when any are found.
- **Prefix-lists nothing references.** Inert entries that filter and announce
  nothing, usually left by a change that was never finished.

`compare` puts two devices side by side. A redundant pair is *supposed* to
differ — different loopbacks, different peering addresses, deliberate traffic
engineering — so a raw diff of two `device.yaml` files runs to thousands of
lines with the real finding buried in it. This reports the shape of the
difference: what exists on only one side, what shares a name but differs, and
what is merely renumbered. Names that closely resemble each other across the two
devices are called out as probable typos.

Neither touches the database or needs the HMAC key; they read the mirror.

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
| NX-OS | supported — features, VXLAN/NVE, VLAN-to-VNI, nested BGP |
| ASA, IOS-XR | detected, no parser — reported as unsupported |
| Firepower / FTD | out of scope: arrives as `fmc_*` REST endpoints, not a flat config |

An unsupported platform is reported rather than producing an empty model that
would look valid.

## Running it in a container

```bash
docker build -t netconfig-mirror:0.1.0 .
docker/run.sh inventory
docker/run.sh sync --push
```

The image holds the installed tool and no source, no configuration and no
secrets. The HMAC key, the database settings and the SSH key used to push are
mounted at run time by `docker/run.sh`, which validates every path first —
bind-mounting a path that does not exist makes Docker create an empty directory
there, and the failure then surfaces as a confusing error about the wrong thing.

Database credentials are mounted as a file and read by the tool's own
`--env-file`, not passed with Docker's: Docker's copies them into the container
environment, where `docker inspect` shows them.

Because the build stage is separate, moving to shipping a prebuilt image later
changes only where `docker build` runs — the artefact is the same.

## Scheduling

```bash
sudo cp docker/netconfig-mirror*.service docker/netconfig-mirror.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netconfig-mirror.timer
systemctl list-timers netconfig-mirror.timer
```

A failed run triggers `netconfig-mirror-failure.service`, which logs to the
journal and mails if `ALERT_EMAIL` is set. Point `notify-failure.sh` at whatever
this organisation actually reads.

### Acknowledging known failures

Copy `docker/acknowledged.example` to `docker/acknowledged.txt` and list
hostnames whose failure is already known and being handled upstream. They stay
in every summary but stop setting the attention exit code.

Without this the scheduled run alerts every night for the same two devices, and
an alert that fires nightly gets muted — which costs you the one that matters.
Acknowledge a device only after raising it with whoever can fix it; the file is
a record of "we know", not a place to hide findings.

## Being called by another service

`networkdiscovery-app` triggers a sync by starting a GitLab pipeline, and reads
results straight from the mirror repository — no bespoke API to deploy or secure.
A pipeline already provides the job id, status endpoint, serialisation, history,
logs and failure notification that such an API would have had to reinvent.

See [`docs/CALLING-FROM-AN-APP.md`](docs/CALLING-FROM-AN-APP.md). Pipeline and
runner configuration are in `docker/gitlab-ci.example.yml` and
`docker/runner-config.example.toml`.

The split that matters: **trigger a pipeline to refresh, read files to query.**
A pipeline is a job, not a query — everything the mirror knows is already sitting
in the repository as files that GitLab serves directly.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | modelled successfully |
| 2 | redaction refused — a credential line came out unredacted |
| 3 | no parser for the detected platform |
| 4 | device not found, ambiguous, or never captured |
| 5 | batch finished, but something needs a person to look at it |
| 6 | the mirror repository could not be used as given |

Code 2 is the one to take seriously. Since the viewer sanitises upstream, it
most likely means **that** sanitiser has a gap — a finding to report there, not
only to patch here.
