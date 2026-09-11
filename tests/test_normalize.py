from netconfig_mirror.normalize import normalize


def test_volatile_timestamp_lines_do_not_reach_the_output():
    """The core anti-churn guarantee: two identical configs captured at
    different times must normalise to byte-identical content."""
    first = (
        "!\n! Last configuration change at 11:45:33 EST Wed Sep 2 2026 by alice@corp.example\n"
        "!\nhostname R1\n"
    )
    second = (
        "!\n! Last configuration change at 09:02:10 EST Thu Sep 3 2026 by bob@corp.example\n"
        "!\nhostname R1\n"
    )
    assert normalize(first)[0] == normalize(second)[0]


def test_author_and_timestamp_are_kept_as_provenance():
    text = "! Last configuration change at 11:45:33 EST Wed Sep 2 2026 by alice@corp.example\nhostname R1\n"
    _, prov = normalize(text)
    assert prov.last_changed_at.startswith("11:45:33")
    assert prov.last_changed_by == "alice"  # domain dropped by default


def test_email_domain_can_be_kept_when_audit_requires_it():
    text = "! Last configuration change at 10:00:00 EST Mon Sep 1 2026 by alice@corp.example\n"
    _, prov = normalize(text, keep_email_domain=True)
    assert prov.last_changed_by == "alice@corp.example"


def test_asa_header_moves_into_provenance():
    text = ": Serial Number: FCH1234ABCD\n: Hardware:   ASA5555, 16384 MB RAM\nhostname FW\n"
    out, prov = normalize(text)
    assert prov.serial == "FCH1234ABCD"
    assert prov.hardware.startswith("ASA5555")
    assert "Serial Number" not in out


def test_cryptochecksum_is_dropped():
    """It digests the pre-redaction config, so post-redaction it verifies
    nothing and can only mislead."""
    out, _ = normalize("hostname FW\nCryptochecksum:1a2b3c4d5e6f\n")
    assert "Cryptochecksum" not in out


def test_byte_count_header_is_dropped():
    out, _ = normalize("! Current configuration : 8123 bytes\nhostname R1\n")
    assert "8123" not in out


def test_trailing_whitespace_does_not_create_a_diff():
    assert normalize("hostname R1   \n")[0] == normalize("hostname R1\n")[0]


def test_output_ends_with_exactly_one_newline():
    out, _ = normalize("hostname R1\n\n\n")
    assert out == "hostname R1\n"


def test_form_feed_in_a_banner_does_not_split_the_line():
    """str.splitlines() breaks on \\x0c and would corrupt legacy MOTD banners.
    The collector does not normalise line endings, so this input is realistic."""
    text = "hostname R1\nbanner motd ^\x0cRESTRICTED ACCESS\x0c^\ninterface Gi0/0\n"
    out, _ = normalize(text)
    assert "banner motd ^\x0cRESTRICTED ACCESS\x0c^" in out
    # Count with CR/LF only -- using str.splitlines() here would reproduce the
    # very bug this test exists to catch.
    assert len(out.rstrip("\n").split("\n")) == 3


def test_crlf_and_lf_normalise_identically():
    """Netmiko line endings vary by vendor; the same config must not diff
    just because it was collected through a different driver."""
    assert normalize("hostname R1\r\ninterface Gi0/0\r\n")[0] == \
           normalize("hostname R1\ninterface Gi0/0\n")[0]


def test_lone_cr_is_treated_as_a_line_break():
    out, _ = normalize("hostname R1\rinterface Gi0/0\r")
    assert out == "hostname R1\ninterface Gi0/0\n"
