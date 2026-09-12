# netconfig-mirror — High-Level Architecture

**Goal.** Turn raw router configurations stored in a Postgres collector database into a
structured, schema-validated YAML model, and mirror that model into a Git repository so
that *every change to the network becomes a reviewable commit*.

**Direction.** One-way: `Postgres → Git`. The repo is an auditable mirror and a drift
detector, never a source of truth that gets pushed back to devices. Nothing in this
system writes to a network device.

**Source.** The **viewer** database. This pipeline runs in the viewer environment and has
no route to a collector's local database. That is a hard constraint, and it costs one
capability outright — see §4.1.

---

## 1. Deployment topology (Azure)

Two VMs on the same VNet:

```
        VM-COLLECTOR                                    VM-GIT
 ┌────────────────────────────┐                 ┌──────────────────────┐
 │  collector  ──▶ Postgres   │                 │  Docker              │
 │                 (localhost)│                 │   └─ GitLab CE       │
 │                     ▲      │                 │       (private repo) │
 │                     │      │                 └──────────▲───────────┘
 │            ┌────────┴────┐ │                            │
 │            │  PIPELINE   │ │────── git push (SSH) ──────┘
 │            │ (this repo) │ │        deploy key
 │            └─────────────┘ │
 └────────────────────────────┘
```

**The pipeline runs on VM-COLLECTOR.** Rationale:

- Postgres binds to `localhost` only and is never exposed across the VNet.
- The only cross-VM traffic is an outbound `git push` over SSH — a single NSG rule,
  one direction, one port.
- If the Git VM is down, the pipeline still produces artifacts locally and pushes on
  the next run. A Git outage cannot cost us a capture.

The reverse layout (pipeline on VM-GIT) would require exposing the database across the
network and is rejected for that reason.

---

## 2. Pipeline stages

Five stages, each producing an inspectable artifact on disk. Any stage can be re-run
against the previous stage's output without touching the database.

### Stage 1 — Extract
Reads the collector DB with a **read-only role**. Pulls the raw config text plus
provenance: device name, site, captured-at timestamp, and the source row identifier.
Writes a local cache so that later stages, debugging, and re-parsing never re-query
the DB.

### Stage 2 — Detect
Identifies `(platform, os_version)` per config: IOS, IOS-XE, NX-OS, IOS-XR, ASA.
This is the dispatch key for the whole parsing layer — the requirement is explicit that
parsing depends on OS version, so the version is a first-class field, not a comment.

### Stage 3 — Parse / Normalize
Dispatches to a parser resolved by `(platform, version-range)` with a fallback chain:

```
exact version match  →  platform default  →  generic hierarchical parse
```

Produces the layered model described in §3. Every parser reports **coverage**: how many
input lines it consumed versus ignored (see §5).

### Stage 4 — Redact & Render
Redaction runs *before* anything is written to a Git-tracked path — see §4. Then renders
deterministic YAML: sorted keys, stable list ordering, no volatile fields. Each file is
validated against a versioned JSON Schema before it is allowed into the repo.

### Stage 5 — GitOps
Compares the rendered content hash against what is already committed. Devices whose
content is unchanged are skipped entirely. Devices that changed are committed and pushed.

---

## 3. The model: three layers

Layered so that the project delivers value on week one and deepens without a redesign.

| Layer | Content | Purpose |
|-------|---------|---------|
| **L0** | Raw config, verbatim, redacted | Ground truth. A parsing gap becomes a *gap*, never data loss. |
| **L1** | Common facts across all platforms: hostname, os/version, interfaces, VRFs, static routes, BGP, OSPF, ACLs, VLANs, SNMP, NTP, AAA, users | The actual model. What most questions get answered from. |
| **L2** | Per-platform sections added on demand | Grows with need, not upfront. |

**L0 is not optional.** No parser covers 100% of a real production config. Keeping the
original alongside the model is what makes an incomplete parser acceptable rather than
dangerous.

Every rendered file carries a `schema_version`. Schemas live in the repo under
`schemas/` and are versioned; a breaking model change is a new schema version, not an
in-place edit.

---

## 4. Redaction — a first-class stage

These are customer production configs. Redaction is not a post-processing nicety; it
runs before any Git-tracked write, and a device that fails redaction is not committed.

### 4.1 What reading from the viewer costs us

The viewer sync masks every credential with the constant literal
`[OMITTED_BY_SANITIZER]`. Every secret collapses to the same string, so **a rotated
credential produces no diff in the mirror**. Rotating a pre-shared key, an enable secret
or an SNMP community is invisible here.

This is not an implementation gap — the signal is absent from the source data and cannot
be reconstructed downstream. Auditing credential rotation would require a second pipeline
running against a collector's local database, which the current environment does not
allow. Recorded so it is not rediscovered as a surprise months from now.

Values arriving with the upstream marker are left **verbatim**, not rewritten to a token
of ours: replacing them would claim we performed the redaction when it happened upstream,
and a reader should be able to tell the two apart.

### 4.2 Our rules are the second net

Because the source is pre-sanitised, our rule set is no longer the primary defence — it
verifies the upstream sanitiser. A residual therefore usually means **the viewer's
sanitiser has a gap**, which is a finding to escalate upstream rather than only a missing
rule here.

The rules still run. A sanitiser we do not own, whose failure mode is silent, is not
something to take on trust.

### 4.3 Staleness is a first-class signal

The viewer keeps no history of its own. Each sync runs
`DELETE FROM devices WHERE collector_id = 'X'` and reinserts whatever the collector
currently holds, triggered by the end of a collection run rather than a fixed schedule.

So a collector that stops - decommissioned, scheduler wedged, credentials expired -
leaves its devices frozen in the viewer at their last known state, unmarked. Those
devices then produce **no diff at all**, which in a mirror is indistinguishable from a
device that is genuinely stable. The system reports calm exactly when it has gone blind.

`collected_at` survives the sync unmodified, so this is detectable. `freshness.py` turns
it into a committed `reports/freshness.md` where a device crossing the staleness
threshold produces a diff of its own.

That report records the capture timestamp and a state, never a computed age: "last seen
38 hours ago" would move on every run and churn the repository for every device forever,
which is the same failure §5 exists to prevent.

### 4.4 Git becomes the durable history

Worth stating plainly, because it reframes what this project is worth: the viewer's
content is replaced wholesale on every sync, and the collector has no retention policy.
**The Git repository therefore becomes the only durable record of what the network looked
like over time.** That is the argument for the backup discipline in
`infra/gitlab/README.md` §6.

**Removed:** password hashes (`password 7`, `secret 5|8|9`), SNMP community and v3 keys,
BGP/OSPF/IKE/pre-shared keys, certificates and key blobs, TACACS/RADIUS keys.

**Method:** each secret is replaced by a stable token derived from an **HMAC** of the
value, keyed by a secret held outside the repo:

```
snmp-server community <redacted:a3f19c>
```

This matters: the token is stable, so an *unchanged* password produces no diff, and a
*rotated* password produces a visible diff — without the value ever reaching the repo.
A plain hash would be crackable for weak passwords; the HMAC key prevents that.

**Not removed:** hostnames, IP addressing, VRF names. They are the entire point of the
mirror. This is why the repository must be **private** — the redacted output still
identifies the customer and their topology.

---

## 5. Two properties that decide whether this succeeds

### Coverage must be measured
Each run reports, per device, the percentage of config lines the model accounts for.
Without this number there is no way to distinguish "we modelled this device" from
"we silently discarded half of it". Coverage is tracked in the repo and its regression
is a defect.

### Noise must be filtered, or every run is a diff
Captured configs contain volatile lines that change with no operator action:
`ntp clock-period`, `! Last configuration change at ...`, `! NVRAM config last updated`,
certificate serials, counters. If these reach the repo, every sync produces a commit,
the signal drowns, and nobody reads the diffs.

A normalization filter strips them before hashing and rendering. **This is the single
biggest threat to the project's usefulness** — a mirror that always shows changes is
worth the same as one that never does.

---

## 6. Repository layout (the mirror repo)

```
inventory/
  <site>/             # devices.location: LD5, DC4, AM5, CLL, ...
    <device>/
      device.yaml     # structured model
      raw.cfg         # redacted configuration, verbatim
      meta.yaml       # provenance and coverage; written only when content changed
reports/
  freshness.md        # devices that stopped being captured
```

`reports/freshness.md` lists **only stale devices**, with healthy ones reduced to a
count. The obvious version tabulates every device with its last capture time - and
every run brings a fresh capture, so every row moves, so the file changes daily. A
staleness report that produces a daily commit is the same churn this project exists to
detect, reintroduced by the tool meant to detect it.

**Commit granularity:** one commit per pipeline run, touching only the devices that
actually changed. The subject names the change count; the body lists the devices.
`git log -- inventory/<site>/<device>/` still gives clean per-device history, so
per-device commits buy nothing and add noise.

**Provenance is written only alongside a real change.** `meta.yaml` carries
`collected_at` and `row_id`, which move on every capture whether or not the device
did. Writing it unconditionally would dirty every device nightly and commit a change
that is not one. Writing it only when the content beside it changed also makes its
timestamp mean the right thing: *when the configuration we are holding was captured*,
not when we last looked.

**Collisions resolve by `device_id`, not by structure.** The obvious fix for two
devices sharing a name is to add the datacenter or the tenant to the path, and in this
estate it does not work: the one real collision is two devices both called `Kernel`, in
the same site and the same collector. A colliding name therefore takes a short suffix
derived from the stable `device_id`. Getting this wrong fails silently - two devices in
one directory produce no error, just a device that appears to reconfigure itself
completely every day.

**Deletion is defended against.** A device absent from the database may be
decommissioned, or the collector may have broken - and the two look identical. Removals
are only considered on a complete, unfiltered run, and a run that would remove more
than 10% of the mirror refuses. An upstream outage must not be able to empty the
history.

---

## 7. Phases

| Phase | Deliverable | Value at completion |
|-------|-------------|---------------------|
| **P0** | GitLab CE on VM-GIT, private repo, deploy key, network path verified | Infrastructure ready |
| **P1** | Extract + L0: redacted raw configs mirrored into Git | **Already useful** — diffable config history |
| **P2** | L1 model for the dominant platform (IOS/IOS-XE) + JSON Schema | Structured, queryable model |
| **P3** | Coverage reporting + NX-OS, IOS-XR, ASA parsers | Full estate covered |
| **P4** | Scheduled runs (systemd timer) + drift alerting | Autonomous operation |

P1 ships a working, valuable system before a single line of the structured model exists.
That ordering is deliberate.

---

## 8. Stack

- **Python 3.11+**, `psycopg` (read-only DB role)
- **pydantic v2** — model definitions, and JSON Schema generated from them rather than
  hand-maintained in parallel
- **ciscoconfparse2** — config hierarchy walking
- **PyYAML / ruamel.yaml** — deterministic rendering, sorted keys
- **git via subprocess** — predictable and debuggable; no library abstraction over it
- **GitLab CE** in Docker on VM-GIT; GitLab CI optionally runs schema validation on push

---

## 9. Security posture

- Postgres: dedicated **read-only** role for the pipeline; bound to `localhost`.
- GitLab: no public IP; NSG restricts access to the VNet and admin sources; TLS with a
  real certificate; the GitLab data volume is backed up.
- Git auth: an SSH **deploy key** scoped to write to this one project only.
- The mirror repo is **private**, permanently. See §4 on why redaction does not make it
  safe to publish.
- The HMAC redaction key lives outside the repo and is never committed.

---

## 10. Findings from the LAC1 sample

Stages 2-4 were built and validated against the six real LAC1 captures (2x 4500X IOS
15.2, 1x 4500X L3, 2x ASR1006, 1x ASA5555). Four things came out of that which were not
predictable from the design:

**The NMS export already masks secrets.** Every credential value in those captures is a
run of asterisks or a short placeholder — there are no real hashes in them. That is good
news for the sample data, but it says nothing about the Postgres source: the collector
talks to devices directly, so those rows most likely hold *unmasked* configs. Redaction
stays, and stays fail-closed. **Validating redaction against real database rows is a
blocking prerequisite before the first push** (see §12).

Collector-masked values are canonicalised to a single `<redacted:presanitised>` token
rather than hashed, because an exporter that writes `*****` in one capture and `**` in
the next would otherwise diff on every sync for a credential that never changed.

**IOS-XE 15.x is not distinguishable by version number.** The ASR1006s report
`version 15.5`, exactly like classic IOS 15.x. The common shortcut of keying on
`version 16/17` labels every IOS-XE 3.x box as `ios` and routes it to the wrong parser.
The markers that actually hold are platform commands — `platform punt-keepalive`,
`subscriber templating` — and they must be matched in their negated form too
(`no platform punt-keepalive disable-kernel-core` is how it appears in the real config).

**Detection is scored, not first-match-wins.** Each platform accumulates weighted marker
hits; a margin below 4 between the top two is reported as low confidence instead of being
resolved silently. That is what made the IOS-XE misdetection visible rather than a wrong
answer delivered with confidence.

**The fail-closed audit earns its place.** On first run against real configs it caught 13
credential lines that the initial rule set missed — three ASA `ikev2` pre-shared-key
spellings among them. Without it, those would have been committed.

---

## 10.1 Command census (viewer database, 2026-09-11)

`SELECT command, count(*), min/max(collected_at) FROM raw_outputs GROUP BY command` over
the live viewer returned ~60 distinct commands. Four results changed the design:

**`show running-config` is there and is current** — 7,590 rows, most recent capture the
same day. The mirror's primary artifact is healthy.

**`show startup-config` is also collected** — 3,331 rows. Not planned for, and worth
having: a device whose running configuration differs from its startup configuration
**silently reverts on reboot**. Mirroring both makes that divergence a visible diff, which
is a genuine operational finding and costs almost nothing once the running config is
already being mirrored. Available behind `all_config_commands(include_startup=True)`;
turning it on is a decision, not a default.

**Juniper and Palo Alto have never been collected.** Both are listed as supported
platforms, but neither `show configuration` nor `show config running` appears anywhere in
the data. The speculative command spellings written for them were removed: dead code that
reads like coverage is worse than an honest gap. `UNKNOWN_COMMANDS` surfaces them if they
ever arrive.

**Firepower/FTD has no flat configuration command.** Its state arrives as seven separate
FMC REST endpoints (`fmc_device_detail`, `fmc_interfaces`, `fmc_acp`, `fmc_routes`,
`fmc_nat`, ...), almost certainly JSON rather than CLI text. Mirroring it means deciding
how to compose several endpoints into one artifact and how to normalise JSON for diffing
— a different problem from mirroring CLI text. **Explicitly out of scope for P1**, and
FTD devices are reported as unsupported rather than silently missing.

### Staleness is already real

Command-level last-capture times confirm §4.3 is not hypothetical:

| Commands | Rows | Last capture | Age |
|---|---|---|---|
| `show running-config`, `show startup-config` | 7,590 / 3,331 | 2026-09-11 | current |
| `fmc_*` | ~2,550 | 2026-09-08 | 2 days |
| `show ip route vrf public_untrusted` | 75 | 2026-08-27 | 15 days |
| `show route ipv4`, `show bgp summary`, `show vrf all detail` (IOS-XR) | 14 | 2026-05-17 | **116 days** |

The IOS-XR command family was collected for roughly three days in May 2026 and never
again. That is command-level evidence, not device-level, so it could equally mean the
collector's command set changed as that the devices went away — but it is exactly the
shape of signal the mirror is supposed to make impossible to miss, and today nothing
anywhere reports it.

---

## 11. Open questions

1. **Which collector writes the DB** (Oxidized, RANCID, a vendor NMS, in-house)? Its
   schema determines Stage 1 entirely.
2. **Estate size and platform mix** — device count and OS-version spread drive how many
   parser variants Stage 3 actually needs.
3. **Sync cadence** — per collector run, hourly, or daily?
4. **Author identity in provenance.** `Last configuration change ... by <user>` is useful
   audit signal but is personal data. Default keeps the local part only (`alice`, not
   `alice@customer.example`); confirm that is the right line.
5. **Redaction policy sign-off** — confirm the §4 lists before anything is committed.

---

## 12. Prerequisite before the first push

Run the redaction audit over a platform-diverse sample of **real rows from the viewer
database** and confirm zero residuals.

The rule set has only ever been validated against pre-masked data, so its coverage of
real credential formats remains unproven. Here a residual means the upstream sanitiser
let something through — the case this net exists to catch — and it must be escalated,
not silenced by adding a local rule and moving on.
