# Bringing up the pipeline trigger

Six steps, each with a check that must pass before moving on. Stopping at a
failed check is the point: every one of these fails in a way that is confusing
if discovered two steps later.

Assumes GitLab is reachable and the mirror repository already exists and has
been pushed to at least once.

---

## 1. Install the runner, as the right user

The runner will read the HMAC key, the SSH push key and the mirror checkout —
all owned by `supportteam` with restrictive permissions. Installing the runner
under its own `gitlab-runner` user means it cannot read any of them, and the
failure appears much later as a permission error inside the container.

```bash
curl -L --proto '=https' --tlsv1.2 -sSf \
  https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh | sudo bash
sudo apt-get install -y gitlab-runner

# Reinstall the service under the account that owns the files.
# Create the working directory first: the service does not create it, and
# without it the runner dies on startup with "chdir ...: no such file or
# directory" and systemd restarts it forever.
sudo -u supportteam mkdir -p /home/supportteam/gitlab-runner

sudo gitlab-runner uninstall
sudo gitlab-runner install --user supportteam \
     --working-directory /home/supportteam/gitlab-runner
sudo usermod -aG docker supportteam
sudo systemctl restart gitlab-runner
```

### Clear `~/.bash_logout` for that user

The shell executor runs the job through `su ... bash -l`, and Ubuntu's default
`~/.bash_logout` ends with:

```bash
if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
```

`clear_console` fails without a TTY, and being the last command in the file it
becomes the login shell's exit status. The runner reports that as
`prepare environment: exit status 1` — a message that points at the environment
and says nothing about a logout script.

It also hides from the obvious test: `sudo -u supportteam bash --login -c 'echo
ok'` exits 0, because `SHLVL` is not 1 there and the block never runs. Only the
runner's own `su` reproduces it.

```bash
cp ~/.bash_logout ~/.bash_logout.bak 2>/dev/null || true
echo 'true' >> ~/.bash_logout        # guarantees a zero exit, changes nothing else
```

Reproduce what the runner actually does, before and after:

```bash
sudo su -s /bin/bash supportteam -c 'bash -l -c "echo ok"'; echo "exit=$?"
```

**Check 1**

```bash
systemctl is-active gitlab-runner          # active
ps -o user= -C gitlab-runner | sort -u     # supportteam
sudo -u supportteam docker ps >/dev/null && echo "docker OK"
```

All three must pass. If `docker ps` fails, the group change has not taken
effect — log out and back in, or reboot.

---

## 2. Register it against GitLab

**Check which address the runner can actually reach first.** The runner is on
the same VM as GitLab, and a VM behind Azure's NAT usually cannot reach its own
public address:

```bash
curl -sk -o /dev/null -w 'public:  %{http_code}\n' --max-time 5 https://<public>:8444/
curl -sk -o /dev/null -w 'private: %{http_code}\n' --max-time 5 https://<private>:8444/
```

A `000` means no connection at all. Register against whichever answers — and if
that is the private address while the certificate names only the public one,
reissue it covering both before going further:

```bash
sudo SSL_DIR=/srv/gitlab/ssl scripts/bootstrap-selfsigned.sh <public> <private>
docker exec gitlab gitlab-ctl restart nginx
```

The first name stays the CN and the filename, so it must still match
`GITLAB_FQDN`; the others are added as SANs. `external_url` does not change —
people keep reaching it by the public address, and only the runner uses the
private one.

The certificate is self-signed, so the runner must also be told to trust it
explicitly. Without `--tls-ca-file` registration fails with a TLS error that
reads like a network problem.

In GitLab: **the mirror project → Settings → CI/CD → Runners → New project
runner**. Tag it `netconfig-mirror`, untick "Run untagged jobs", create it, and
copy the authentication token.

```bash
sudo gitlab-runner register \
  --non-interactive \
  --url https://4.175.164.71:8444/ \
  --token <authentication token> \
  --executor shell \
  --shell bash \
  --description netconfig-mirror \
  --tls-ca-file /srv/gitlab/ssl/4.175.164.71.crt
```

**Check 2** — in GitLab, the runner shows a green dot on the project's Runners
page. A grey dot means it registered but is not polling; check
`journalctl -u gitlab-runner -n 50`.

---

## 3. Give the job its environment

```bash
sudo $EDITOR /etc/gitlab-runner/config.toml
```

Set `concurrent = 1` at the top, and add the `environment` array from
`docker/runner-config.example.toml` to the `[[runners]]` section. These are host
paths, not values: the secrets stay in files that only a host administrator can
change.

Two things about where it goes:

- It must sit **inside `[[runners]]` and before `[runners.cache]`**. In TOML a
  bare key written after a sub-table header belongs to that sub-table, so an
  `environment` placed below `[runners.cache]` is silently attached to the cache
  settings and never reaches the job.
- Write it on **one line**. A multi-line array pasted into an editor is easy to
  truncate, and the resulting error — `expected value but found "runners"` —
  points at the next section rather than at the missing bracket.

```bash
sudo gitlab-runner verify        # rejects a malformed config before restarting
sudo systemctl restart gitlab-runner
systemctl is-active gitlab-runner
```

**Check 3**

```bash
grep -A3 environment /etc/gitlab-runner/config.toml
sudo -u supportteam test -r /home/supportteam/.netconfig-mirror.key && echo "key readable"
sudo -u supportteam test -w /home/supportteam/modeler/mirror && echo "mirror writable"
```

---

## 4. Add the pipeline

Copy `docker/gitlab-ci.example.yml` into the mirror repository as
`.gitlab-ci.yml`, commit and push.

```bash
cp ~/modeler/dt_model/docker/gitlab-ci.example.yml ~/modeler/mirror/.gitlab-ci.yml
cd ~/modeler/mirror
git add .gitlab-ci.yml
git commit -m "Add the sync pipeline"
git push
```

**Check 4** — pushing must NOT start a pipeline. The `rules` block restricts it
to trigger, schedule and web. If a pipeline appears on push, the rules did not
apply, and every sync commit would start another one in a loop. Fix that before
continuing.

---

## 5. Run it by hand first

**the project → Build → Pipelines → Run pipeline**, on `main`.

**Check 5** — the job goes green, and:

```bash
git -C ~/modeler/mirror log --oneline -3
```

Either a new sync commit is there, or the job log ends in
`nothing changed; no commit`. Both are correct outcomes; a red job is not.

Do this before involving a trigger token. A failure here is about the runner,
the environment or permissions — and separating that from token problems saves
an hour.

---

## 6. Trigger it over the API

**Settings → CI/CD → Pipeline trigger tokens → Add new token.**

```bash
curl -k -X POST \
  -F token=<trigger token> \
  -F ref=main \
  https://4.175.164.71:8444/api/v4/projects/<project_id>/trigger/pipeline
```

The project id is on the project's landing page, under the name.

**Check 6** — the response contains a pipeline `id`, and that pipeline appears
and goes green. Then poll it the way the app will:

```bash
curl -k -H "PRIVATE-TOKEN: <project access token, read_api>" \
  https://4.175.164.71:8444/api/v4/projects/<project_id>/pipelines/<id>
```

`status` should read `success`.

Only now is it worth handing anything to whoever maintains
`networkdiscovery-app`: everything up to this point has been verified without
them.

---

## Serialisation is worth verifying once

```bash
for i in 1 2 3; do
  curl -k -s -X POST -F token=<trigger token> -F ref=main \
    https://4.175.164.71:8444/api/v4/projects/<id>/trigger/pipeline \
    | grep -o '"id":[0-9]*'
done
```

Three pipelines are created; `resource_group` makes them run one after another,
never together. Two concurrent syncs would both write the mirror's working tree
and leave the repository inconsistent — worth seeing it hold with your own eyes
once, because nothing in the normal flow will ever show you.

---

## What to hand over

`docs/CALLING-FROM-AN-APP.md`, plus:

- the GitLab base URL and project id
- a trigger token (starting syncs, and nothing else)
- a project access token with `read_api` and `read_repository`

The trigger token is not a read credential: whoever holds it can ask for a
refresh and learn nothing else.
