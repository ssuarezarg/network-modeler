# Triggering a sync from another service

`networkdiscovery-app` asks for a mirror update by starting a GitLab pipeline,
and reads results straight out of the mirror repository. There is no bespoke API
to deploy, authenticate or keep running.

The division that makes this work:

| Need | Mechanism | Latency |
|---|---|---|
| "Refresh the mirror" | Trigger a pipeline | Seconds to start, minutes to finish |
| "What does device X look like?" | Read the file from the repo | Immediate |
| "What did it look like in July?" | Read the file at an older commit | Immediate |

**Do not trigger a pipeline to answer a question.** A pipeline is a job, not a
query: it costs seconds of start-up and has to be polled. Everything the mirror
knows is already sitting in the repository as files, and GitLab serves those
directly.

---

## Asking for a sync

### 1. Start it

```http
POST https://<gitlab>/api/v4/projects/<project_id>/trigger/pipeline
Content-Type: application/x-www-form-urlencoded

token=<trigger token>&ref=main
```

Optionally limit it to one site:

```
token=<trigger token>&ref=main&variables[SITE]=DC4
```

The response carries the pipeline `id`, which is the job identifier.

```json
{ "id": 42, "status": "created", "web_url": "https://.../pipelines/42" }
```

The trigger token comes from **Settings → CI/CD → Pipeline trigger tokens** on
the mirror project. It can start pipelines and nothing else — it cannot read the
repository or the API.

### 2. Poll for the result

```http
GET https://<gitlab>/api/v4/projects/<project_id>/pipelines/42
PRIVATE-TOKEN: <project access token with read_api>
```

`status` moves through `created` → `pending` → `running` → `success` | `failed`.

This needs a *different* token: a project access token with `read_api`. Trigger
tokens are write-only by design.

### 3. Concurrency is already handled

The pipeline declares `resource_group: mirror-sync`, so a second request while
one is running waits rather than racing. Two simultaneous syncs would both write
the mirror's working tree and leave the repository inconsistent; this is the one
thing a hand-written API would have had to get right, and GitLab does it in a
single line.

The app does not need to serialise its own calls.

### 4. What `failed` means

The pipeline fails when the tool's exit code is non-zero. The ones worth
distinguishing, visible in the job log:

| Code | Meaning | Who acts |
|---|---|---|
| 2 | A credential came through unredacted | Escalate: the viewer's sanitiser has a gap |
| 5 | Finished, but something unacknowledged needs attention | Network/collector owner |
| 6 | The mirror repository could not be used | Whoever administers the VM |

A `failed` pipeline does **not** mean the mirror is corrupt. Exit 5 in
particular means the sync completed and committed normally.

---

## Reading the model

Everything is a file. `inventory/<site>/<device>/`:

| File | Contents |
|---|---|
| `device.yaml` | the structured model |
| `raw.cfg` | the redacted configuration, verbatim |
| `meta.yaml` | provenance, coverage figures, redaction counts |

```http
GET /api/v4/projects/<id>/repository/files/
    inventory%2Fdc4%2Fdc4-edge-r1%2Fdevice.yaml/raw?ref=main
PRIVATE-TOKEN: <project access token with read_repository>
```

The path must be URL-encoded — `/` becomes `%2F`.

### History for free

```http
GET /api/v4/projects/<id>/repository/commits?path=inventory/dc4/dc4-edge-r1
```

Then request the same file with `?ref=<commit sha>` to see the device as it was
at that point. No extra storage, no extra endpoint: this is what putting the
mirror in Git buys.

### Listing what exists

```http
GET /api/v4/projects/<id>/repository/tree?path=inventory/dc4&ref=main
```

### Devices that stopped being captured

`reports/freshness.md` lists only stale devices. A device that stopped being
collected produces no diff of its own — its configuration simply stops changing,
which is indistinguishable from a device that is genuinely stable. That file is
the only place the difference is visible.

---

## Tokens to create

| Token | Scope | Used for |
|---|---|---|
| Pipeline trigger token | — | Starting a sync |
| Project access token | `read_api` | Polling pipeline status |
| Project access token | `read_repository` | Reading models and history |

The last two can be one token with both scopes. Keep them out of source: they
belong wherever `networkdiscovery-app` already keeps its secrets.

**The trigger token is not a read credential.** Anyone holding it can start
syncs and learn nothing else — which is the right shape for a service that only
ever needs to say "please refresh".
