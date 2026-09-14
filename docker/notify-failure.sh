#!/usr/bin/env bash
# Called by systemd when a sync run fails. Keep it short and make it reach
# someone.
#
# Exit codes worth distinguishing, from the tool:
#   2  redaction refused — a credential came through unredacted. Since the
#      viewer sanitises upstream, that most likely means THAT sanitiser has a
#      gap: escalate there, do not just patch here.
#   5  finished, but something needs attention that is not acknowledged
#   6  the mirror repository could not be used (dirty, missing, not a repo)
#   other — the run did not complete
set -euo pipefail

UNIT="${1:-netconfig-mirror.service}"
STATUS="$(systemctl show -p ExecMainStatus --value "$UNIT" 2>/dev/null || echo '?')"

case "$STATUS" in
  2) REASON="REDACTION REFUSED - a credential was not redacted. Escalate to whoever owns the collector's sanitiser." ;;
  5) REASON="finished with findings that need attention (see the run output)" ;;
  6) REASON="the mirror repository could not be used - dirty working tree, missing, or not a repository" ;;
  *) REASON="the run did not complete" ;;
esac

MESSAGE="netconfig-mirror: $REASON (exit $STATUS)"

# Always to the journal, at a severity that shows up in `journalctl -p warning`.
logger -t netconfig-mirror -p daemon.err "$MESSAGE"

# And to a human, if this host can send mail. Replace with whatever this
# organisation actually reads - Slack webhook, Teams, a monitoring API.
if command -v mail >/dev/null 2>&1 && [[ -n "${ALERT_EMAIL:-}" ]]; then
  {
    echo "$MESSAGE"
    echo
    systemctl status --no-pager --lines=50 "$UNIT" || true
  } | mail -s "netconfig-mirror failed on $(hostname)" "$ALERT_EMAIL"
fi
