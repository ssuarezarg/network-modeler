# GitLab CE on VM-GIT (Azure) — deployment runbook

Phase **P0** of netconfig-mirror: stand up the Git server that will hold the mirror
repository, and prove the network path from VM-COLLECTOR.

Assumes a private VM with **no public IP**, reached over the VNet from a bastion or VPN.

---

## 1. VM and disk prerequisites

**Size:** 4 vCPU / 8 GB is what GitLab CE actually needs (`Standard_D2s_v5` is 2/8 and
works; `Standard_D4s_v5` is comfortable). On 4 GB it runs but swaps badly under
`gitlab-ctl reconfigure` — if that is what you have, add a swap file and use the reduced
sizing noted in `.env.example`.

**Disk — the one Azure-specific trap:**

Attach a **managed data disk** and mount it at `/srv/gitlab`.

- **Never use `/mnt`.** On Azure that is the ephemeral resource disk. It is wiped when
  the VM is deallocated or moved to another host. A GitLab instance stored there
  disappears on the first stop/start, with no error until you look for it.
- Do not use the OS disk either — it is 30 GB by default and GitLab will fill it.

```bash
# Identify the new disk (typically /dev/sdc; verify before touching anything)
lsblk

sudo parted /dev/sdc --script mklabel gpt mkpart primary ext4 0% 100%
sudo mkfs.ext4 /dev/sdc1
sudo mkdir -p /srv/gitlab

# Mount by UUID, never by device name: Azure does not guarantee sd* ordering
# across reboots, and a wrong-device fstab entry can leave the VM unbootable.
UUID=$(sudo blkid -s UUID -o value /dev/sdc1)
echo "UUID=$UUID  /srv/gitlab  ext4  defaults,nofail  0  2" | sudo tee -a /etc/fstab
sudo mount -a
df -h /srv/gitlab      # confirm before continuing
```

`nofail` matters: without it, a disk that fails to attach stops the VM from booting and
you lose SSH access to fix it.

**Kernel setting for Redis:**

```bash
echo 'vm.overcommit_memory=1' | sudo tee /etc/sysctl.d/60-gitlab.conf
sudo sysctl --system
```

---

## 2. Network (NSG)

| Port | Source | Purpose |
|------|--------|---------|
| 8443 | VNet + admin range | HTTPS: web UI and `git clone https://` |
| 2222 | **VM-COLLECTOR only** | git+ssh — the pipeline's push path |
| 22 | Bastion / admin only | Host SSH for VM administration |
| 8480 | VNet | Redirects to HTTPS only. Optional; omit to force HTTPS-only |

**Why non-standard ports:** this VM also runs NetBox, which holds 80/443. GitLab publishes
on 8443/8480 instead, while nginx inside the container still listens on 443/80
(`nginx['listen_port']`). Two consequences worth knowing before first boot:

- `GITLAB_HTTPS_PORT` is written into `external_url`, and GitLab bakes that into every
  clone URL and post-login redirect it issues. Changing it later needs a reconfigure and
  breaks remotes people already have. **Decide the port before first boot.**
- Omnibus normally derives nginx's internal port from `external_url`. Left alone, a
  `:8443` URL would make nginx listen on 8443 *inside* the container and the `8443:443`
  mapping would match nothing. `nginx['listen_port'] = 443` pins it and keeps host port
  and URL port independent.

Outbound from VM-COLLECTOR to VM-GIT on 2222 is the only cross-VM flow the pipeline
needs. The database is never reachable from this VM.

Port 22 on the host belongs to the VM's own sshd, which is why GitLab's git+ssh listens
on 2222. **Do not move the host sshd to free up 22** — a mistake there locks you out of
a VM that has no public IP.

---

## 3. TLS certificate

The omnibus Let's Encrypt integration is disabled in the compose file, and cannot work
here: HTTP-01 validation requires inbound port 80 from the internet, which a private VM
does not have. Two workable options:

1. **Internal CA (recommended).** Issue a certificate for `${GITLAB_FQDN}` with the FQDN
   in the SAN, and place it as `/srv/gitlab/ssl/<fqdn>.crt` and `<fqdn>.key`.
2. **Public CA via DNS-01.** If the domain is publicly delegated, a DNS-01 challenge
   issues a valid certificate without any inbound connectivity. Renewal must be
   automated separately — omnibus will not do it.

To get the instance up before a certificate is issued:

```bash
sudo ./scripts/bootstrap-selfsigned.sh gitlab.internal.example.com
```

Read that script's header first — a self-signed certificate forces clients to disable TLS
verification, which is a bad habit to establish around this repository. Replace it before
anyone clones.

---

## 4. First boot

```bash
cp .env.example .env
$EDITOR .env                      # FQDN, BIND_ADDR, sizing
sudo mkdir -p /srv/gitlab/{config,logs,data,backups,ssl}

docker compose config             # verify substitution before starting
docker compose up -d
docker compose logs -f gitlab     # first reconfigure takes 5-10 minutes
```

Wait for the health status to go green:

```bash
docker inspect --format '{{.State.Health.Status}}' gitlab
```

**Initial root password** — generated on first boot, not set in the compose file
(anything in `environment:` is readable by anyone who can run `docker inspect`):

```bash
docker exec -it gitlab cat /etc/gitlab/initial_root_password
```

That file is deleted automatically after 24 hours. Log in, change the password, and then:

- **Disable public sign-up** (Admin → Settings → General → Sign-up restrictions). It is
  on by default.
- Set visibility default to **Private**. Per `docs/ARCHITECTURE.md` §4, the mirror repo
  stays private permanently — redaction removes secrets but hostnames, IP addressing and
  VRF names remain, and those identify the customer.

---

## 5. Repository and deploy key

Create a private project (e.g. `netops/netconfig-mirror`), then on **VM-COLLECTOR**:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/netconfig-mirror -C 'netconfig-mirror pipeline' -N ''
cat ~/.ssh/netconfig-mirror.pub
```

Add the public key in GitLab under **Project → Settings → Repository → Deploy keys**,
with **write access enabled**. A project deploy key — not a personal account key — so the
pipeline's access is scoped to this one repository and survives staff changes.

Then on VM-COLLECTOR:

```bash
cat >> ~/.ssh/config <<'CONF'
Host gitlab-mirror
  HostName gitlab.internal.example.com
  Port 2222
  User git
  IdentityFile ~/.ssh/netconfig-mirror
  IdentitiesOnly yes
CONF

# Proves DNS, NSG, sshd and the deploy key all work, in one command:
ssh -T gitlab-mirror
git clone gitlab-mirror:netops/netconfig-mirror.git
```

That clone succeeding is the completion criterion for P0.

---

## 6. Backups

`scripts/backup.sh` produces both required artifacts. Read its header: a backup taken
without `/etc/gitlab` (which holds `gitlab-secrets.json`) restores with all encrypted
data permanently unreadable.

```bash
sudo install -m 700 scripts/backup.sh /usr/local/bin/gitlab-backup.sh
sudo crontab -e
# 02:00 daily
0 2 * * * /usr/local/bin/gitlab-backup.sh >> /var/log/gitlab-backup.log 2>&1
```

Backups land in `/srv/gitlab/backups`, mounted separately from the live data so they can
be synced to Blob Storage (`azcopy`, or an Azure Backup job on the disk) without touching
the data volume. **A backup that never leaves the VM does not protect against losing the
VM.**

Verify a restore once, on a throwaway VM, before treating any of this as protection.

---

## 7. Upgrades

`GITLAB_VERSION` is pinned deliberately. GitLab enforces an upgrade path — you cannot
jump multiple majors, and each step runs irreversible database migrations.

Before any upgrade: take a backup (§6), confirm the target version is a legal next hop on
GitLab's upgrade path, then bump `GITLAB_VERSION`, `docker compose pull`, and
`docker compose up -d`.

Never run `latest` here. An unattended pull that crosses a major version migrates the
database on startup, and the only way back is the backup you may not have taken.
