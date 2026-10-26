# How the mirror works, end to end

A briefing for people who will use the mirror or rely on it, rather than build
it. For the API calls in detail see
[`CALLING-FROM-AN-APP.md`](CALLING-FROM-AN-APP.md); for the reasoning behind the
design, [`ARCHITECTURE.md`](ARCHITECTURE.md).

Substitute for your deployment:

| Placeholder | What it is |
|---|---|
| `<gitlab>` | host and port of the GitLab holding the mirror |
| `<project-id>` | numeric project id, shown on the project's landing page |
| `<group>/<project>` | the mirror repository's path |
| `<trigger-token>` | pipeline trigger token (`glptt-…`) |
| `<read-token>` | project access token with `read_api` and `read_repository` |

---

## The flow

```
  collector database                    this tool                      GitLab
 ┌────────────────────┐        ┌───────────────────────┐        ┌────────────┐
 │  raw_outputs       │───1───▶│ normalise             │        │            │
 │  devices           │        │   strip volatile      │        │   mirror    │
 └────────────────────┘        │ redact                │───5───▶│  repository │
          ▲                    │   fail closed         │        │            │
          │                    │ detect platform       │        └────────────┘
   nightly captures            │ parse → model         │              ▲
   from the network            │ commit only changes   │              │
                               └───────────────────────┘        git log / diff
                                          ▲                     the whole history
                        POST /trigger/pipeline
```

1. **Extract** — read-only, one snapshot per run: the latest capture of each
   device. No watermark, because rows can reach the database long after they
   were taken, and a watermark would skip them permanently.

2. **Normalise** — remove lines that move on their own: capture timestamps,
   byte counts, checksums. Left in, every sync commits every device nightly and
   the real changes drown.

3. **Redact** — replace credentials with keyed tokens, and **fail closed**: a
   credential line no rule recognises stops that device rather than being
   published.

4. **Parse** — dispatch on `(platform, version)` to a model: interfaces, VRFs,
   VLANs, BGP, OSPF, static routes, ACLs, prefix-lists and route-maps.

5. **Commit** — write into the repository and commit only what actually
   changed. A network that did not change produces no commit.

---

## Asking for a refresh

```bash
curl -X POST -F token=<trigger-token> -F ref=main \
  https://<gitlab>/api/v4/projects/<project-id>/trigger/pipeline
```

Returns a pipeline `id`. Add `-F "variables[SITE]=<site>"` to limit the run to
one location.

```bash
curl -H "PRIVATE-TOKEN: <read-token>" \
  https://<gitlab>/api/v4/projects/<project-id>/pipelines/<id>
```

`status` goes `created` → `running` → `success`.

Concurrent requests are serialised by the pipeline's `resource_group`: a second
request waits rather than racing. Two syncs at once would both write the
repository's working tree and leave it inconsistent, so callers do not need to
coordinate.

### The pipeline always shows the commit before the one it made

A pipeline is bound to a commit when it is created, and never updated. So the
pipeline page shows whatever was at the tip of `main` when it was triggered —
which is the commit the *previous* run produced — while the repository has
already moved on to the commit this run just made.

```
a6cf020  sync: 3 changed    the repository's HEAD, made by this run
a786bec  sync: 5 changed    what the pipeline page shows
```

Nothing is wrong: producing the next commit is the job's whole purpose, so it
cannot be the commit the pipeline started from. It is more noticeable here than
in ordinary CI because the pipeline runs with `GIT_STRATEGY: none` and never
checks the repository out at all — the associated commit is purely a label for
what the state was at the start.

The commit the run actually created is named near the end of the job log:

```
committed a6cf020: 3 changed, 0 renamed, 0 removed
pushed
```

---

## Reading the mirror

**Do not trigger a pipeline to answer a question.** A pipeline is a job, not a
query, and everything the mirror knows is already sitting in the repository as
files.

```bash
# one device
curl -H "PRIVATE-TOKEN: <read-token>" \
  "https://<gitlab>/api/v4/projects/<project-id>/repository/files/\
inventory%2F<site>%2F<device>%2Fdevice.yaml/raw?ref=main"

# when it changed
curl -H "PRIVATE-TOKEN: <read-token>" \
  "https://<gitlab>/api/v4/projects/<project-id>/repository/commits\
?path=inventory/<site>/<device>"

# how it looked then — same file, older commit
curl -H "PRIVATE-TOKEN: <read-token>" \
  ".../device.yaml/raw?ref=<commit-sha>"
```

Paths must be URL-encoded: `/` becomes `%2F`.

---

## Reading a sync commit

```bash
git show --stat <sha>                    # which devices changed
git show <sha> -- '*/device.yaml'        # what changed, in the model
git show <sha> -- '*/raw.cfg'            # the same change in the configuration
```

The model diff is the one to read first: it groups and orders, so a changed BGP
neighbour or interface description is two lines instead of being scattered
through a couple of thousand.

**When `device.yaml` shows nothing and `raw.cfg` shows plenty, that is a
finding about the model, not a quiet commit.** Something real changed in a part
of the configuration the model does not cover yet, and the mirror caught it only
because it keeps the configuration verbatim alongside.

That signal is worth acting on, because it says what to model next from evidence
rather than from guesswork. It is how prefix-lists and route-maps came to be
modelled: six devices changed together, `device.yaml` was identical on all six,
and the change turned out to be a hundred new prefix-list entries in the routing
policy toward the transit carriers — the part of these configurations that
people actually edit.

`meta.yaml` changes alongside any real change and carries the coverage figures
for that capture, so a drop in `accounted` between two commits is the same kind
of signal: the device grew configuration the parser has never seen.

---

## What it produces

```
inventory/<site>/<device>/
    device.yaml     the structured model
    raw.cfg         the redacted configuration, verbatim
    meta.yaml       provenance, coverage figures, redaction counts
reports/
    freshness.md    devices that stopped being captured
```

Sites come from the collector's `devices.location`, with a hostname convention
as fallback.

`raw.cfg` is kept beside the model deliberately. No parser covers every line of
a real configuration, and holding the original means an incomplete parser is a
gap rather than lost data.

`reports/freshness.md` lists **only stale devices**. A device that stopped being
collected produces no diff of its own — its configuration simply stops changing,
which is indistinguishable from a device that is genuinely stable. That file is
the only place the difference is visible.

---

## Reading the coverage figures

```
modelled     : 545 (59.1%)
accounted    : 99.6% (modelled + recognised)
unrecognised : 4 lines
```

**Two numbers on purpose.** *Modelled* is the share of configuration lines that
produced content in the model. *Accounted* adds lines that are recognised but
deliberately not modelled — service toggles, spanning-tree, class-maps.
Counting recognition as modelling would push the figure to 99% and make it
meaningless.

**The gap between *accounted* and 100% is what nobody has looked at yet** — the
only number that says whether the parser is finished for a platform. The
`unrecognised` list is ordered by frequency, so the next thing worth parsing is
chosen from evidence.

A low *modelled* figure is not necessarily bad: an access switch whose
configuration is mostly AAA and line settings will score low and still be fully
accounted for.

Current figures for your estate:

```bash
netconfig-mirror inventory      # platforms, sites, tenants, bad captures
```

---

## Questions the mirror can answer

```bash
netconfig-mirror audit --repo <path>                     # policy that cannot work
netconfig-mirror compare <device-a> <device-b> --repo <path>
```

**`audit`** finds route-maps and BGP neighbours referencing a prefix-list that
does not exist. Worth acting on: such a reference does not fail — it matches
nothing, so the policy the engineer believed they applied was never applied, and
nothing anywhere reports it.

Confirm each against `raw.cfg` before reporting it. A name can also appear there
because the parser failed to recognise the definition, which is a fault in the
tool and not on the device.

**`compare`** reports the *shape* of the difference between two devices rather
than its text. A redundant pair is supposed to differ — different loopbacks,
different peering addresses, deliberate traffic engineering — so a raw diff runs
to thousands of lines with the real finding buried in it. This reports what
exists on only one side, what shares a name but differs, and what is merely
renumbered, and flags names that look like a typo of one another.

---

## Exit codes

| Code | Meaning | Who acts |
|---|---|---|
| 0 | Finished cleanly | — |
| 2 | A credential came through unredacted | Escalate to whoever owns the upstream sanitiser |
| 5 | Finished, but something unacknowledged needs attention | Network or collector owner |
| 6 | The mirror repository could not be used | Whoever administers the host |

A failed pipeline does **not** mean the mirror is corrupt. Exit 5 in particular
means the sync completed and committed normally.

Findings already raised belong in the acknowledgement file: they stay in every
summary and stop setting the attention exit code, so a scheduled run is quiet
until something *new* goes wrong. An alert that fires every night gets muted,
and then it costs you the one that matters.

The file takes two kinds of entry, which do not collide:

```
UK-LD5-R316-RTR1                                  # a device's collection failure
dangling:HK1-L3-SW:route-map static-into-bgp:redistribute-static-into-bgp
```

Generate the keys rather than typing them:

```bash
netconfig-mirror audit --repo <path> --ack-file <file> --keys >> <file>
```

`--keys` prints only findings that are not yet acknowledged, so re-running it
appends what is new and nothing else. Read what it appended before committing:
every line means "this is known and somebody is dealing with it", and a finding
parked there that nobody is working on is worse than no file at all, because it
now looks handled. A key is built from the structural parts —
device, what refers, what it refers to — and never from the sentence describing
the finding, because that sentence carries a "did you mean …?" suggestion that
changes as the device changes. An acknowledgement keyed on the sentence would
silently stop matching, and the finding would start alerting again with nothing
to explain why.

The key carries the device's **hostname**, which belongs to the device, and
not its path in the mirror, which encodes the site the collector reports for
it. Paths were used first, to tell apart two devices sharing a name. They
broke within three days: the collector split one site into two — the
data-quality fix that had been asked for — every path moved, and six
acknowledgements stopped matching and re-reported as new findings. Tying the
key to the field most likely to be corrected was the mistake.

Acknowledging a finding on one device therefore covers the same finding on
any device of that name. Where two records share a name because they are the
same device captured twice, that is what you want. Where they are genuinely
two devices it is not, and the name is the thing to fix — so the report lists
every hostname held by more than one device directory, which keeps the
coarseness visible instead of built into a key nobody reads.

A key written in the older path form is still honoured, so a file written
while paths were the key keeps working rather than re-reporting everything in
it at once. The report also lists acknowledgements that match no finding:
either the finding was fixed and the entry can go, or the key stopped
matching — which looks exactly like a new finding, and is how six known
issues re-reported themselves as fresh ones.

---

## What it deliberately does not do

**Write to devices.** Read-only, always.

**Detect credential rotation**, when the source database is already sanitised.
If every secret arrives replaced by one constant literal, a rotated password
produces no diff: the signal is absent from the source and cannot be recovered
downstream.

**Model every platform.** Firepower arrives as REST endpoints rather than a
configuration, and is mirrored and versioned rather than modelled. An
unsupported platform is reported as such rather than yielding an empty model
that would look valid.
