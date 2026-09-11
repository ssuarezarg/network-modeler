#!/usr/bin/env bash
# GitLab backup — run from cron on VM-GIT.
#
# Two artifacts, and BOTH are required for a restore:
#   1. The repository/database backup (gitlab-backup create).
#   2. /etc/gitlab, which holds gitlab-secrets.json.
#
# gitlab-secrets.json holds the keys that encrypt CI/CD variables, 2FA secrets
# and stored tokens. A backup restored WITHOUT the matching secrets file comes
# back with all of that unreadable and unrecoverable. This is the single most
# common way a GitLab backup turns out to be worthless.
set -euo pipefail

CONTAINER="${CONTAINER:-gitlab}"
CONFIG_BACKUP_DIR="${CONFIG_BACKUP_DIR:-/srv/gitlab/backups/config}"
KEEP_DAYS="${KEEP_DAYS:-7}"

log() { printf '%s  %s\n' "$(date -Is)" "$*"; }

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  log "ERROR: container '$CONTAINER' is not running; nothing was backed up."
  exit 1
fi

log "Starting repository + database backup"
# CRON=1 silences progress output so cron only mails on genuine errors.
docker exec -t "$CONTAINER" gitlab-backup create CRON=1

log "Backing up /etc/gitlab (contains gitlab-secrets.json)"
mkdir -p "$CONFIG_BACKUP_DIR"
stamp="$(date +%Y%m%d-%H%M%S)"
docker exec -t "$CONTAINER" tar -czf - -C /etc gitlab \
  > "${CONFIG_BACKUP_DIR}/etc-gitlab-${stamp}.tar.gz"

# The config archive contains secrets in cleartext. Owner-only, always.
chmod 600 "${CONFIG_BACKUP_DIR}/etc-gitlab-${stamp}.tar.gz"

log "Pruning config backups older than ${KEEP_DAYS} days"
# Repository backups are pruned by GitLab itself via backup_keep_time; only the
# config archives are ours to clean up.
find "$CONFIG_BACKUP_DIR" -name 'etc-gitlab-*.tar.gz' -mtime "+${KEEP_DAYS}" -delete

log "Backup complete: ${CONFIG_BACKUP_DIR}/etc-gitlab-${stamp}.tar.gz"
