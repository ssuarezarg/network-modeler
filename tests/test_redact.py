import pytest

from netconfig_mirror.redact import (
    PRESANITISED_TOKEN,
    RedactionError,
    audit_residuals,
    redact,
    redact_or_raise,
    token,
)

KEY = b"test-key"
OTHER_KEY = b"different-key"


def test_secrets_are_replaced_by_tokens():
    text = "enable secret 9 $9$abcdEFGH1234\n"
    out, report = redact(text, KEY)
    assert "$9$abcdEFGH1234" not in out
    assert "<redacted:" in out
    assert out.startswith("enable secret 9 ")  # line shape preserved
    assert report.clean


def test_same_secret_same_token_across_runs():
    """No diff when nothing changed -- the whole point of a stable token."""
    text = "username admin secret 9 $9$saltyhash\n"
    first, _ = redact(text, KEY)
    second, _ = redact(text, KEY)
    assert first == second


def test_rotated_secret_produces_a_visible_diff():
    before, _ = redact("username admin secret 9 $9$oldhash\n", KEY)
    after, _ = redact("username admin secret 9 $9$newhash\n", KEY)
    assert before != after


def test_token_depends_on_the_key():
    """Without this, tokens would be plain hashes and crackable offline."""
    assert token("hunter2", KEY) != token("hunter2", OTHER_KEY)


def test_missing_key_is_refused():
    with pytest.raises(RedactionError):
        redact("enable secret 9 $9$x\n", b"")


@pytest.mark.parametrize(
    "line",
    [
        "enable secret 9 $9$hash",
        "enable password 7 070C285F4D06",
        "username ops privilege 15 secret 5 $1$salt$hash",
        " ikev1 pre-shared-key SuperSecret1",
        " ikev2 local-authentication pre-shared-key SuperSecret2",
        " ikev2 remote-authentication pre-shared-key SuperSecret3",
        "snmp-server community pubsecret RO",
        "snmp-server user u grp v3 auth sha AuthKey123 priv aes 128 PrivKey456",
        " neighbor 10.0.0.1 password 7 1234567890AB",
        "  key-string 7 0822455D0A16",
        "tacacs-server host 10.0.0.5 key 7 04480E051A33",
        "ldap-login-password SomePassword",
    ],
)
def test_every_known_credential_family_is_caught(line):
    out, report = redact(line + "\n", KEY)
    assert report.clean, f"residual on: {line}"
    assert "<redacted:" in out


def test_hash_surviving_in_an_unknown_command_is_a_residual():
    """Fail closed: a hash in a command no rule knows must stop the device.
    This is the case that protects us from vendor syntax we have never seen."""
    assert audit_residuals("some-future-vendor-credential $9$leftoverhash\n")


def test_redact_or_raise_refuses_to_emit_on_residual():
    with pytest.raises(RedactionError):
        redact_or_raise("some-future-vendor-credential $9$leftoverhash\n", KEY)


def test_clean_input_passes_redact_or_raise():
    out, report = redact_or_raise("enable secret 9 $9$realhash\nhostname R1\n", KEY)
    assert "$9$realhash" not in out
    assert report.total == 1


def test_residual_report_never_contains_the_secret():
    residuals = audit_residuals("key-string 7 0822455D0A16SECRETVALUE\n")
    assert residuals
    for _, excerpt in residuals:
        assert "0822455D0A16SECRETVALUE" not in excerpt


def test_collector_masked_values_are_canonicalised():
    """`*****` and `**` are the same non-secret: they must not churn the diff."""
    wide, _ = redact(" ikev1 pre-shared-key *****\n", KEY)
    narrow, _ = redact(" ikev1 pre-shared-key **\n", KEY)
    assert PRESANITISED_TOKEN in wide
    assert wide == narrow


def test_value_less_credential_line_is_not_a_residual():
    """The LAC1 exporter emits `!!enable secret 9` with the value stripped."""
    assert not audit_residuals("!!enable secret 9\n")


def test_snmp_user_without_auth_clause_is_benign():
    assert not audit_residuals("snmp-server user wcsuser wcsuser v3\n")


def test_two_secrets_on_one_line_are_both_redacted():
    """NX-OS puts the auth key and the privacy key on the same line. Redacting
    only the first left the second in cleartext -- and the audit passed it,
    because a line containing a token looked handled."""
    line = ("snmp-server user admin network-admin auth md5 AUTHKEY1234567890 "
            "priv aes-128 PRIVKEY0987654321 localizedV2key\n")
    out, report = redact(line, KEY)
    assert "AUTHKEY1234567890" not in out
    assert "PRIVKEY0987654321" not in out
    assert report.clean


def test_partially_redacted_line_is_still_audited():
    """Being partly redacted is not proof of being safe."""
    partial = ("snmp-server user admin grp auth md5 <redacted:aabbccdd> "
               "priv aes-128 0123456789ABCDEF0123 localizedV2key\n")
    assert audit_residuals(partial)


def test_nxos_and_ios_privacy_cipher_spellings():
    """IOS writes `priv aes 128`, NX-OS writes `priv aes-128`. Matching only one
    leaves the key in cleartext on the other platform."""
    for spelling in ("aes 128", "aes-128", "aes-256", "des", "3des"):
        line = f"snmp-server user u g auth sha AUTH1234567890AB priv {spelling} SECRETKEY123456789\n"
        out, report = redact(line, KEY)
        assert "SECRETKEY123456789" not in out, spelling
        assert report.clean, spelling


def test_iosxr_encrypted_keyword_between_algorithm_and_hash():
    line = ("snmp-server user snmpv3adm V3-RO-GROUP v3 auth sha encrypted "
            "022A05592A131B297C4F1A priv aes 128 encrypted 12350415221905121A\n")
    out, report = redact(line, KEY)
    assert "022A05592A131B297C4F1A" not in out
    assert "12350415221905121A" not in out
    assert report.clean


def test_iosxr_credential_on_an_indented_child_line():
    """IOS-XR writes the password under `username`, not on the same line:
        username cisco
         password 7 <hash>
    so every rule keyed to the username line misses it."""
    config = "username cisco\n group root-lr\n password 7 04785A150C2E1D1C5A4D50\n"
    out, report = redact(config, KEY)
    assert "04785A150C2E1D1C5A4D50" not in out
    assert report.clean


def test_a_token_is_never_tokenised_again():
    """A broader rule running after a narrower one must leave the existing token
    alone; re-hashing it would stop it tracking the underlying value."""
    once, _ = redact("username admin secret 9 $9$realhash\n", KEY)
    twice, _ = redact(once, KEY)
    assert once == twice


def test_snmp_engine_id_is_not_reported_as_a_leak():
    """An engine ID is long hex but identifies the agent, not key material.
    Flagging it would block devices for no reason."""
    line = ("snmp-server user u g v3 engineID 80000009fe9455adb4856c56308530364cd3 "
            "encrypted auth sha <redacted:aabbccdd>\n")
    assert not audit_residuals(line)


SECRET = "N0tARealKey2026"


def _redacted(line: str) -> str:
    out, _ = redact(line if line.endswith("\n") else line + "\n", KEY)
    return out


def test_interface_and_protocol_keys_are_redacted():
    """None of these are exotic. They sit on ordinary IOS interfaces across the
    estate, and every one was reaching the mirror in cleartext while the
    residual audit reported nothing."""
    for line in (
        f" ip ospf message-digest-key 1 md5 {SECRET}",
        f" ip ospf authentication-key {SECRET}",
        f" standby 1 authentication md5 key-string {SECRET}",
        f" standby 1 authentication text {SECRET}",
        f"ntp authentication-key 1 md5 {SECRET}",
    ):
        assert SECRET not in _redacted(line), line


def test_asa_shared_keys_are_redacted():
    """`server-key` under aaa-server, and the failover key. Neither is spelled
    `key`, which is why both were missed."""
    assert SECRET not in _redacted(f" server-key {SECRET}")
    assert SECRET not in _redacted(f"failover key {SECRET}")


def test_a_password_at_the_end_of_an_unfamiliar_line():
    assert SECRET not in _redacted(
        f" http-proxy 10.0.0.1 port 80 username operator password {SECRET}")


def test_a_key_chain_keeps_its_identifiers_and_loses_its_secrets():
    """`\\s` matches a newline, so a rule anchored on one line reached into the
    next: ` key 1\\n  key-string <secret>` had the *word* `key-string`
    tokenised, leaving the secret beside it and a redaction marker on the line
    that made the audit read it as handled."""
    out = _redacted(f"key chain OSPF-KEYS\n key 1\n  key-string {SECRET}\n")

    assert SECRET not in out
    assert " key 1\n" in out          # the identifier is model data
    assert "key-string <redacted:" in out


def test_credential_words_that_carry_no_secret_are_left_alone():
    """Each of these appears in the LAC1 firewall. Redacting a reference breaks
    the model; flagging one fails a device every night for nothing."""
    for line in (
        "ssh key-exchange group dh-group14-sha256",
        "key chain OSPF-KEYS",
        " key 1",
        "crypto key generate rsa modulus 2048",
        " authentication key-chain OSPF-KEYS",
        "aaa-server cisco protocol ldap",
        " set ikev1 transform-set ESP-AES-256",
        "no service password-encryption",
        " password-storage enable",
        "username guest nopassword",
    ):
        out = _redacted(line)
        assert out.strip() == line.strip(), line
        assert not audit_residuals(out), line


def test_the_net_catches_a_spelling_no_rule_knows():
    """The point of the net. It used to enumerate the same spellings as the
    rules, so a rule missing one left the net missing it too."""
    assert audit_residuals(f" some-vendor-shared-secret {SECRET}\n")


BGP_COMMUNITIES = """ set community 65000:100 additive
 neighbor 68.64.76.169 send-community both
 send-community extended
ip bgp-community new-format
 description *** carrier circuit - key account contact ***
"""


def test_bgp_communities_are_not_credentials():
    """`community` in IOS is overwhelmingly BGP. Treating the bare word as a
    credential refused 46 of 71 devices on the first real run - a redaction
    refusal skips the device, so a net this broad silently stops mirroring
    most of the estate."""
    out, _ = redact(BGP_COMMUNITIES, KEY)

    assert out == BGP_COMMUNITIES
    assert not audit_residuals(out)


def test_an_snmp_trap_receiver_community_is_a_credential():
    """The same word after `snmp-server host` is the community string, and it
    had no rule at all until widening the net pointed at it."""
    out, report = redact(
        "snmp-server host inside 10.0.0.1 community TrapString version 2c\n", KEY)

    assert "TrapString" not in out
    assert report.counts.get("snmp-host-community") == 1
