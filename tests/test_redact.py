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
