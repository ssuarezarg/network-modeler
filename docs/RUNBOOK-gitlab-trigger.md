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

# Reinstall the service under the account that owns the files
sudo gitlab-runner uninstall
sudo gitlab-runner install --user supportteam \
     --working-directory /home/supportteam/gitlab-runner
sudo usermod -aG docker supportteam
sudo systemctl restart gitlab-runner
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

The certificate is self-signed, so the runner must be told to trust it
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

Set `concurrent = 1` at the top, and add the `environment` block from
`docker/runner-config.example.toml` to the `[[runners]]` section. These are host
paths, not values: the secrets stay in files that only a host administrator can
change.

```bash
sudo systemctl restart gitlab-runner
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
