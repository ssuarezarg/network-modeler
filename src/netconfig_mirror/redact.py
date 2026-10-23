"""Secret redaction. Runs before anything reaches a Git-tracked path.

Design contract, in order of importance:

0. **We are the second net, not the first.** The pipeline reads the viewer
   database, which the upstream sync has already sanitised with the literal
   `[OMITTED_BY_SANITIZER]`. So a residual here usually means the *viewer\'s*
   sanitiser has a gap, and is a finding to escalate upstream rather than just a
   missing rule on our side. The rules below still run, because a sanitiser we
   do not own and whose failure mode is silent is not something to take on
   trust.

1. **Fail closed.** A line that looks like it carries a secret but that no rule
   knows how to handle is a *residual* and stops the device from being
   committed. An unknown credential format must break the pipeline, never slip
   through it. `audit_residuals()` is that check, and it runs on the output, not
   the input.

2. **Stable tokens, not deletion.** Each secret becomes an HMAC-derived token,
   so an unchanged password produces no diff and a rotated one produces a
   visible diff, without the value ever being written down. A plain hash would
   be trivially crackable for weak passwords; the HMAC key (held outside the
   repo) is what prevents that.

3. **Line shape survives.** `enable secret 9 <redacted:ab12cd34>` still parses
   and still tells a reader what kind of credential sat there.

Known limitation: the token covers the *stored ciphertext*, not the underlying
password. Cisco type 7/8/9 are salted, so re-entering the same password produces
different ciphertext and therefore a new token. That reads as a change in the
diff, which is the safe direction to be wrong in.
**This layer has never fired in production.** Across 71 devices the mirror
holds zero `<redacted:` tokens: every credential in the estate arrives already
masked as `[OMITTED_BY_SANITIZER]` by the viewer database's own sanitiser. So
the protection that is actually working is upstream, and this is a net that
has never caught anything.

That is exactly why it could be broken without anyone noticing - six credential
spellings were leaking in cleartext, found only by firing synthetic credentials
at it. Two consequences worth keeping in mind. Its correctness can only ever be
established by tests, never by a clean run against the estate; a clean run
proves nothing, because nothing reaches it. And the day the viewer stops
sanitising, or the mirror is pointed at a source that never did, this becomes
the only thing between a running-config and a Git repository.

"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from hashlib import sha256

# Each rule's regex must expose a group named `secret`; everything else in the
# match is preserved verbatim so the line stays readable and parseable.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    # enable secret 9 <hash> / enable password 7 <hash>
    ("enable", re.compile(
        r"(?P<pre>^\s*!*enable (?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d+)?\s+)(?P<secret>\S+)",
        re.M | re.I)),
    # username x [privilege n] secret|password [type] <hash>
    ("username", re.compile(
        r"(?P<pre>^\s*username\s+\S+(?:\s+privilege\s+\d+)?"
        r"(?:\s+(?:secret|password))(?:\s+\d+)?\s+)(?P<secret>\S+)",
        re.M | re.I)),
    # IPsec pre-shared keys (ikev1/ikev2, IOS and ASA spellings)
    # `ikev2 local-authentication pre-shared-key` and the remote- variant are
    # separate ASA spellings; the first draft of this rule missed both, and the
    # residual audit is what surfaced them.
    ("psk", re.compile(
        r"(?P<pre>^\s*(?:crypto isakmp key\s+"
        r"|ikev[12]\s+(?:(?:local|remote)-authentication\s+)?(?:local-|remote-)?pre-shared-key\s+"
        r"|pre-shared-key\s+(?:address\s+\S+\s+key\s+)?))(?P<secret>\S+)",
        re.M | re.I)),
    # snmp-server community <string> [RO|RW|acl]
    ("snmp-community", re.compile(
        r"(?P<pre>^\s*snmp-server community\s+)(?P<secret>\S+)", re.M | re.I)),
    # The trap-receiver form carries the same string and had no rule at all:
    # `snmp-server host <iface> <addr> [version 2c] <community>`. Found by
    # widening the net, which is what the net is for.
    ("snmp-host-community", re.compile(
        r"(?P<pre>^\s*snmp-server host\s+.*?\bcommunity\s+)(?P<secret>\S+)",
        re.M | re.I)),
    # snmp-server user: auth and priv keys, each on the same line
    ("snmp-v3-auth", re.compile(
        r"(?P<pre>^\s*snmp-server user\s+.*?\bauth\s+\S+\s+(?:encrypted\s+)?)"
        r"(?P<secret>\S+)", re.M | re.I)),
    # Privacy key. The cipher spelling differs by platform - IOS writes
    # `priv aes 128 <key>`, NX-OS writes `priv aes-128 <key>` - and matching
    # only one of them leaves the key in cleartext on the other.
    ("snmp-v3-priv", re.compile(
        r"(?P<pre>\bpriv\s+(?:(?:aes(?:[-\s]\d+)?|3?des)\s+)?(?:encrypted\s+)?)"
        r"(?P<secret>\S+)"
        r"(?=\s+(?:localized\S*key|access)|\s*$)", re.M | re.I)),
    # BGP / routing protocol peer authentication
    ("bgp-password", re.compile(
        r"(?P<pre>^\s*neighbor\s+\S+\s+password(?:\s+\d+)?\s+)(?P<secret>\S+)", re.M | re.I)),
    # key chains, TACACS/RADIUS shared secrets
    ("key-string", re.compile(
        r"(?P<pre>^\s*key-string(?:\s+\d+)?\s+)(?P<secret>\S+)", re.M | re.I)),
    ("aaa-key", re.compile(
        r"(?P<pre>^\s*(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key"
        r"(?:\s+\d+)?\s+)(?P<secret>\S+)", re.M | re.I)),
    # `key 7 <hash>` or `key <secret>` under a tacacs/radius server. The
    # negative lookahead keeps it off `key 1` inside a key chain, where the
    # number is the key's identifier and belongs in the model.
    ("aaa-key-sub", re.compile(
        r"(?P<pre>^\s+key\s+(?!\d+\s*$)(?:\d+\s+)?)(?P<secret>\S+)", re.M | re.I)),
    # A credential on its own indented line. IOS-XR writes:
    #     username cisco
    #      group root-lr
    #      password 7 <hash>
    # so the value never appears on the `username` line the other rules expect.
    ("standalone-credential", re.compile(
        r"(?P<pre>^\s+(?:password|secret)(?:\s+\d+)?\s+)(?P<secret>\S+)\s*$",
        re.M | re.I)),
    # PPP/CHAP
    ("ppp", re.compile(
        r"(?P<pre>^\s*ppp (?:chap|pap sent-username \S+) password(?:\s+\d+)?\s+)"
        r"(?P<secret>\S+)", re.M | re.I)),
    # ASA trailing-keyword form: `... password <value> encrypted`
    ("asa-encrypted", re.compile(
        r"(?P<pre>\bpassword\s+)(?P<secret>\S+)(?=\s+encrypted\b)", re.M | re.I)),
    # ASA's login password, spelled `passwd` and not `password`:
    #     passwd <value> encrypted
    # The viewer's sanitiser masks `enable password` on the same device and
    # leaves this one in cleartext. Found on the first clean run against the
    # estate, by the widened net rather than by any rule.
    ("asa-passwd", re.compile(
        r"(?P<pre>^\s*passwd\s+)(?P<secret>\S+)", re.M | re.I)),
    ("ldap", re.compile(
        r"(?P<pre>^\s*ldap-login-password\s+)(?P<secret>\S+)", re.M | re.I)),
    # Interface and protocol authentication. These are not exotic: they sit on
    # ordinary IOS interfaces across the estate, and every one of them was
    # going to the mirror in cleartext.
    ("ospf-key", re.compile(
        r"(?P<pre>^\s*ip ospf (?:message-digest-key\s+\d+\s+md5|authentication-key)"
        r"(?:\s+\d+)?\s+)(?P<secret>\S+)", re.M | re.I)),
    ("hsrp-key", re.compile(
        r"(?P<pre>^\s*standby\s+\d+\s+authentication\s+"
        r"(?:md5\s+key-string(?:\s+\d+)?|text)\s+)(?P<secret>\S+)", re.M | re.I)),
    ("ntp-key", re.compile(
        r"(?P<pre>^\s*ntp authentication-key\s+\d+\s+\S+\s+)(?P<secret>\S+)",
        re.M | re.I)),
    # ASA: the failover shared key, and the RADIUS/TACACS secret under
    # `aaa-server`, which is spelled `server-key` and not `key`.
    ("asa-shared-key", re.compile(
        r"(?P<pre>^\s*(?:failover\s+key|server-key)(?:\s+\d+)?\s+)(?P<secret>\S+)",
        re.M | re.I)),
    # Last resort: a password as the final value on a line nothing above
    # claimed - `http-proxy ... username u password <value>`. Kept last so the
    # specific rules name the credential they caught.
    ("inline-password", re.compile(
        r"(?P<pre>\bpassword\s+)(?P<secret>\S+)\s*$", re.M | re.I)),
]

# Lines that must contain a redaction token after processing. This is the
# fail-closed net.
#
# It used to enumerate the same spellings as the rules above, which meant it
# could only catch a credential someone had already thought of - and a rule
# missing a spelling left the net missing it too. Six spellings were leaking
# in cleartext with this audit reporting zero residuals, among them OSPF,
# HSRP and NTP keys on ordinary IOS interfaces.
#
# So the net is keyed on credential *words* followed by a value, independent
# of any command it knows. Everything that then reads as a false positive is
# listed in `_BENIGN` by name, where it is visible and reviewable - the
# opposite of being invisibly absent from a list of patterns.
_CREDENTIAL_WORD = (
    r"(?:pre-shared-key|key-string|server-key|authentication-key"
    # `community` is deliberately absent. In IOS it is overwhelmingly BGP -
    # `set community`, `send-community extended`, `ip bgp-community new-format`
    # - and including it refused 46 of 71 devices on the first real run. It is
    # a secret only after `snmp-server`, which the enumerated commands cover.
    r"|message-digest-key|shared-secret|password|passwd|secret"
    # Bare `key`, but not `key-chain` / `key-exchange`, which name a thing
    # rather than carry one.
    r"|key(?![-\w]))"
)
# The enumerated commands stay. Some credentials are not spelled with any
# credential word at all - `snmp-server user ... auth md5 <key> priv aes-128
# <key>` names them `auth` and `priv` - so the word-based net cannot replace
# this list. It adds to it. Replacing one net with a broader-looking one is
# how coverage disappears quietly; the test for two secrets on an SNMPv3 line
# is what caught that happening here.
_SUSPECT_COMMANDS = (
    r"^\s*(?:!*enable (?:secret|password)|username\s+\S+.*\b(?:secret|password)\b"
    r"|.*\bpre-shared-key\b|.*\bcrypto isakmp key\b|snmp-server (?:community|user)\b"
    r"|snmp-server host\s+.*\bcommunity\b"
    r"|.*\bneighbor\s+\S+\s+password\b|key-string\b|.*(?:tacacs|radius)-server.*\bkey\b"
    r"|.*\bppp (?:chap|pap).*\bpassword\b|ldap-login-password\b)"
)
_SUSPECT_LINE = re.compile(
    rf"(?:{_SUSPECT_COMMANDS})|(?:^(?!\s*no\s).*\b{_CREDENTIAL_WORD}\s+\S)", re.I)

# Lines matching a suspect pattern that are nonetheless safe: no value present,
# or the value is a reference rather than a secret.
_BENIGN = re.compile(
    r"^\s*(?:no\s+|.*\b(?:password-storage|password-policy|password encryption aes)\b"
    r"|username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:nopassword|autocommand)\b"
    # snmp-server user without an `auth` clause carries no key (v1/v2c, or a v3
    # user the collector exported without credentials).
    r"|snmp-server user\s+(?!.*\bauth\b).*$"
    # Credential keyword with the value already stripped by the collector:
    # `!!enable secret 9` with nothing following it.
    r"|!*enable\s+(?:secret|password)(?:\s+\d+)?\s*$)"
    # Names and knobs that contain a credential word but carry no secret.
    r"|^\s*key chain\b"
    r"|^\s*key\s+\d+\s*$"
    r"|^\s*crypto key\s+(?:generate|zeroize)\b"
    r"|\bkey-chain\s+\S+\s*$"
    r"|\bkey-exchange\b"
    # Free text. It trips the word-based net on wording alone, and a device
    # refusing every night over its own description is the kind of noise that
    # teaches people to ignore the refusal that matters.
    r"|^\s*description\b"
    # `community` as a BGP or SNMP *view* name rather than a string.
    r"|\bsnmp-server (?:community-map|group)\b",
    re.I,
)

# Encrypted-material shapes that must never survive redaction, whatever rule
# was supposed to catch them.
_LEAK_SHAPES = [
    re.compile(r"\$(?:1|5|6|8|9)\$[^\s<]{6,}"),          # unix-style hashes
    re.compile(r"\bpassword\s+7\s+[0-9A-Fa-f]{8,}"),      # Cisco type 7
]

# A long run of hex on a credential-bearing line is almost certainly key
# material. Used only on suspect lines, so ordinary hex elsewhere is untouched.
_HEX_SECRET = re.compile(r"(?<![\w$:.-])[0-9A-Fa-f]{16,}(?![\w:.-])")

# Long hex that is legitimately not a secret. An SNMP engine ID identifies the
# agent and is not key material; flagging it would block devices for no reason.
_BENIGN_HEX_CONTEXT = re.compile(r"\bengine(?:id|-id)\b", re.I)


@dataclass
class RedactionReport:
    counts: dict[str, int] = field(default_factory=dict)
    residuals: list[tuple[int, str]] = field(default_factory=list)
    # Values that arrived already masked by the viewer's sanitiser. A count of
    # zero on a device that should have credentials is itself worth noticing.
    upstream_sanitised: int = 0

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def clean(self) -> bool:
        return not self.residuals


class RedactionError(RuntimeError):
    """Raised when a device cannot be redacted safely enough to commit."""


# The viewer database sanitises before we ever see it, using this exact literal.
# We read from the viewer, so in practice this is what most credential values
# look like on the way in.
#
# These are left VERBATIM rather than rewritten to a token of ours. Replacing
# them would claim we did the redaction, when in fact it happened upstream and
# the distinction matters for provenance: a reader of the mirror should be able
# to tell which masking they are looking at.
_UPSTREAM_SANITISED = re.compile(r"^\[OMITTED_BY_SANITIZER\]$|^\[[A-Z_]+\]$")

# Width-varying placeholders (the LAC1 NMS export writes runs of asterisks).
# Unlike the marker above these DO get canonicalised, because an exporter that
# writes `*****` in one capture and `**` in the next would otherwise diff on
# every sync for a credential that never changed.
_PRESANITISED = re.compile(r"^(?:\*+|[Xx]+|<[^>]*>)$")

PRESANITISED_TOKEN = "<redacted:presanitised>"


def is_upstream_sanitised(value: str) -> bool:
    return bool(_UPSTREAM_SANITISED.match(value.strip()))


def token(secret: str, key: bytes) -> str:
    """Stable token for one secret value."""
    if _PRESANITISED.match(secret.strip()):
        return PRESANITISED_TOKEN
    digest = hmac.new(key, secret.strip().encode("utf-8", "replace"), sha256).hexdigest()
    return f"<redacted:{digest[:8]}>"


def redact(config_text: str, key: bytes) -> tuple[str, RedactionReport]:
    """Replace every recognised secret with a stable token.

    Returns the redacted text and a report. Call `audit_residuals()` on the
    result — or use `redact_or_raise()` — before writing anything to the repo.
    """
    if not key:
        # Without a key the tokens would be plain hashes: crackable for weak
        # passwords, which is the whole thing this is meant to prevent.
        raise RedactionError("no HMAC key supplied; refusing to redact")

    report = RedactionReport()
    text = config_text

    def _apply(name: str, pattern: re.Pattern[str], _sub) -> None:
        nonlocal text
        # Line by line, never across the whole text. Every rule is anchored
        # with `^` or `$`, but `\s` matches a newline, so `^\s+key\s+(\d+\s+)?
        # (?P<secret>\S+)` applied to the whole config consumed ` key 1\n` and
        # tokenised the first word of the *next* line. In a key chain that is
        # the word `key-string`, which left the secret beside it in cleartext
        # and put a `<redacted:` marker on the line - so the residual audit
        # read it as handled. Scoping each rule to one line removes the whole
        # class rather than this one instance of it.
        text = "\n".join(pattern.sub(_sub, line) for line in text.split("\n"))

    for name, pattern in _RULES:
        def _sub(match: re.Match[str], _name: str = name) -> str:
            secret = match.group("secret")
            if secret.startswith("<redacted:"):
                # Already replaced by an earlier rule. Without this guard a
                # broader rule can tokenise a token, and the second token would
                # no longer track the underlying value at all.
                return match.group(0)
            if is_upstream_sanitised(secret):
                # Already masked by the viewer. Leave the line exactly as it
                # arrived; rewriting it would misattribute the redaction.
                report.upstream_sanitised += 1
                return match.group(0)
            report.counts[_name] = report.counts.get(_name, 0) + 1
            return f"{match.group('pre')}{token(secret, key)}"

        _apply(name, pattern, _sub)

    report.residuals = audit_residuals(text)
    return text, report


def audit_residuals(redacted_text: str) -> list[tuple[int, str]]:
    """Find credential-bearing lines that came out without a token.

    Returned lines are truncated to the part before the value, so the audit
    output itself never carries a secret.
    """
    residuals: list[tuple[int, str]] = []

    for lineno, line in enumerate(redacted_text.splitlines(), start=1):
        handled = "<redacted:" in line or "[OMITTED_BY_SANITIZER]" in line
        suspect = bool(_SUSPECT_LINE.match(line)) and not _BENIGN.match(line)

        if suspect and not handled:
            residuals.append((lineno, _safe_excerpt(line)))
            continue

        # A line can carry more than one secret. `snmp-server user ... auth md5
        # <key> priv aes-128 <key>` holds two, and treating the line as handled
        # because the first one was replaced let the second through with the
        # audit reporting nothing. Being partially redacted is not proof of
        # being safe, so keep checking.
        if suspect and _unredacted_key_material(line):
            residuals.append((lineno, _safe_excerpt(line)))
            continue

        for shape in _LEAK_SHAPES:
            if shape.search(line):
                residuals.append((lineno, _safe_excerpt(line)))
                break

    return residuals


def _unredacted_key_material(line: str) -> bool:
    """Long hex on a credential line that is not an engine ID."""
    for match in _HEX_SECRET.finditer(line):
        before = line[max(0, match.start() - 40):match.start()]
        if _BENIGN_HEX_CONTEXT.search(before):
            continue
        return True
    return False


def redact_or_raise(config_text: str, key: bytes) -> tuple[str, RedactionReport]:
    """Redact, and refuse to return anything if a residual survived."""
    text, report = redact(config_text, key)
    if not report.clean:
        detail = "; ".join(f"line {n}: {frag}" for n, frag in report.residuals[:5])
        raise RedactionError(
            f"{len(report.residuals)} credential line(s) left unredacted - "
            f"refusing to emit. First: {detail}"
        )
    return text, report


# Longest credential keyword we ever emit. Anything longer is assumed to be a
# value, not a keyword.
_MAX_KEYWORD_LEN = 24


def _safe_excerpt(line: str, keep_words: int = 2) -> str:
    """Identify the command, never the value.

    Two words, not three: in `key-string 7 <hash>` the third word IS the secret.
    A residual report gets logged and read by people, so leaking there would
    defeat the mechanism it belongs to. Two tokens are enough to name the
    command family and write the missing rule, and no Cisco credential line
    carries its value that early.
    """
    words = [w for w in line.split() if len(w) <= _MAX_KEYWORD_LEN][:keep_words]
    excerpt = " ".join(words)
    return (excerpt + " ...").strip()
