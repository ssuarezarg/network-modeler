#!/usr/bin/env bash
# Run netconfig-mirror in its container with everything it needs mounted.
#
#   docker/run.sh sync --push
#   docker/run.sh inventory
#   docker/run.sh device dc4-edge-r1
#
# Nothing sensitive is passed as an environment variable. Docker's --env-file
# copies values into the container's environment, where `docker inspect` and
# /proc show them; the database settings are instead mounted as a file and read
# by the tool's own --env-file, so the credentials never become env vars at all.
#
# /etc/passwd is mounted read-only because the container runs as the host's UID,
# which has no entry in the image. OpenSSH calls getpwuid() and refuses to start
# when it cannot resolve the user it is running as - "No user exists for uid
# 1000" - so the push fails even though everything else works. HOME is set to
# the tmpfs for the same reason: the home directory named in that passwd entry
# does not exist inside the container.
#
# Paths are validated before docker runs. Bind-mounting a path that does not
# exist makes Docker create an empty DIRECTORY there, and the failure surfaces
# later as "IsADirectoryError" on what should have been the key file - an error
# that says nothing about the real mistake.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Tag the image with the commit it was built from, and build it on demand.
#
# Updating the code does not update what runs: `git pull` changes the checkout,
# the container keeps the old code, and the fix appears not to work with nothing
# saying why. Deriving the tag from the checkout makes that impossible — a
# different commit is a different tag, and a tag that does not exist yet is
# built before the run.
#
# A modified working tree gets its own `-dirty` tag, so local edits are never
# silently run from a stale image either. The layer cache keeps the rebuild
# quick when only source changed.
if [[ -z "${IMAGE:-}" ]]; then
  revision="$(git -C "$TOOL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if [[ -n "$(git -C "$TOOL_DIR" status --porcelain 2>/dev/null)" ]]; then
    revision="${revision}-dirty"
  fi
  IMAGE="netconfig-mirror:${revision}"
fi
REPO="${REPO:-$HOME/modeler/mirror}"
KEY_FILE="${KEY_FILE:-$HOME/.netconfig-mirror.key}"
ENV_FILE="${ENV_FILE:-$HOME/modeler/dt_model/.env}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/mirror-push}"
KNOWN_HOSTS="${KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
# Optional. Devices whose failure is already known and raised; see
# docker/acknowledged.example. Mounted rather than passed as a path, because a
# host path handed to --ack-file does not exist inside the container - the file
# is then silently absent and every known-bad device demands attention again.
ACK_FILE="${ACK_FILE:-$SCRIPT_DIR/acknowledged.txt}"
# Optional. The container is read-only with nothing but a tmpfs /tmp, so
# anything `device` or `file` writes is gone the moment it exits - which is
# exactly the output you need when inspecting a platform that has no parser
# yet. Set OUT_DIR to a host directory and pass `--out /out`.
OUT_DIR="${OUT_DIR:-}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Docker refuses a relative path for a bind mount, and says so in terms of
# volume names rather than of the path you gave it: "includes invalid
# characters for a local volume name". Catching it here names the variable.
absolute() {
  local name="$1" value="$2"
  [[ "$value" = /* ]] || die "$name must be an absolute path, got: $value"
}

for pair in "REPO:$REPO" "KEY_FILE:$KEY_FILE" "ENV_FILE:$ENV_FILE" \
            "SSH_KEY:$SSH_KEY" "KNOWN_HOSTS:$KNOWN_HOSTS" "ACK_FILE:$ACK_FILE"; do
  absolute "${pair%%:*}" "${pair#*:}"
done

[[ -d "$REPO/.git" ]]   || die "REPO=$REPO is not a git repository. Clone the mirror there first."
[[ -f "$KEY_FILE" ]]    || die "KEY_FILE=$KEY_FILE does not exist. Generate it with: openssl rand -hex 32 > $KEY_FILE"
[[ -f "$ENV_FILE" ]]    || die "ENV_FILE=$ENV_FILE does not exist. Copy .env.example and fill in the database settings."
[[ -f "$SSH_KEY" ]]     || die "SSH_KEY=$SSH_KEY does not exist. Needed to push; generate it with ssh-keygen and add it to GitLab."
[[ -f "$KNOWN_HOSTS" ]] || die "KNOWN_HOSTS=$KNOWN_HOSTS does not exist. Connect once by hand so the host key is recorded."

# Each subcommand takes a different set of these flags, and argparse rejects the
# ones it does not know. Appending them blindly would make `inventory` fail on
# an unrecognised --repo.
SUBCOMMAND="${1:---help}"
EXTRA=()
case "$SUBCOMMAND" in
  sync)      EXTRA=(--repo /mirror --key-file /secrets/hmac.key --env-file /secrets/db.env) ;;
  batch|device|file)
             EXTRA=(--key-file /secrets/hmac.key --env-file /secrets/db.env) ;;
  inventory|volatile)
             EXTRA=(--env-file /secrets/db.env) ;;
  # Read the mirror only: no database, no key.
  compare) EXTRA=(--repo /mirror) ;;
  audit)   EXTRA=(--repo /mirror) ;;
  *)         EXTRA=() ;;
esac

OUT_MOUNT=""
if [[ -n "$OUT_DIR" ]]; then
  absolute "OUT_DIR" "$OUT_DIR"
  mkdir -p "$OUT_DIR" || die "cannot create OUT_DIR=$OUT_DIR"
  OUT_MOUNT="-v $OUT_DIR:/out"
fi

ACK_MOUNT=""
if [[ -f "$ACK_FILE" ]]; then
  ACK_MOUNT="-v $ACK_FILE:/secrets/acknowledged.txt:ro"
  case "$SUBCOMMAND" in
    sync|batch|audit) EXTRA+=(--ack-file /secrets/acknowledged.txt) ;;
  esac
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  printf 'building %s (first run for this commit)\n' "$IMAGE" >&2
  docker build -t "$IMAGE" "$TOOL_DIR" >&2 || die "build failed"
fi

# --network host so the container reaches the database VM and GitLab exactly as
# the host does, without publishing anything or duplicating network config.
exec docker run --rm \
  --name "netconfig-mirror-$$" \
  --network host \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --tmpfs /tmp \
  -v "$REPO:/mirror" \
  -v "$KEY_FILE:/secrets/hmac.key:ro" \
  -v "$ENV_FILE:/secrets/db.env:ro" \
  -v "$SSH_KEY:/secrets/ssh_key:ro" \
  -v "$KNOWN_HOSTS:/secrets/known_hosts:ro" \
  -v /etc/passwd:/etc/passwd:ro \
  ${ACK_MOUNT} \
  ${OUT_MOUNT} \
  -e HOME=/tmp \
  -e GIT_SSH_COMMAND="ssh -i /secrets/ssh_key -o IdentitiesOnly=yes -o UserKnownHostsFile=/secrets/known_hosts" \
  -e GIT_AUTHOR_NAME=netconfig-mirror \
  -e GIT_AUTHOR_EMAIL=netconfig-mirror@local \
  -e GIT_COMMITTER_NAME=netconfig-mirror \
  -e GIT_COMMITTER_EMAIL=netconfig-mirror@local \
  "$IMAGE" \
  "$@" "${EXTRA[@]}"
