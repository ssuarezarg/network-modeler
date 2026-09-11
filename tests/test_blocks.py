from netconfig_mirror.blocks import ConfigDocument


def test_indented_bang_does_not_terminate_a_block():
    """IOS emits indented `!` separators INSIDE blocks -- between BGP
    address-families, for instance. Treating them as terminators orphans every
    line after them into bogus top-level blocks; on a real ASR1006 that lost
    258 neighbor lines."""
    doc = ConfigDocument(
        "router bgp 65001\n"
        " bgp router-id 1.1.1.1\n"
        " !\n"
        " address-family ipv4\n"
        "  neighbor 10.0.0.1 activate\n"
        " exit-address-family\n"
    )
    assert len(doc.blocks) == 1
    assert doc.blocks[0].header == "router bgp 65001"
    assert any("neighbor 10.0.0.1" in child for child in doc.blocks[0].children)


def test_banner_body_is_captured_whole():
    """Banner text is free text, not configuration, and it is not indented.
    Walking it would parse prose as commands."""
    doc = ConfigDocument(
        "banner motd ^C\n"
        "WARNING - authorised access only\n"
        "^C\n"
        "hostname R1\n"
    )
    headers = [b.header for b in doc.blocks]
    assert "hostname R1" in headers
    assert "WARNING - authorised access only" not in headers


def test_banner_text_cannot_invent_configuration():
    """The failure this prevents: a banner mentioning an interface would
    otherwise create a phantom interface in the model."""
    doc = ConfigDocument(
        "banner login ^\n"
        "Contact netops before touching interface GigabitEthernet0/0\n"
        "^\n"
    )
    assert not [b for b in doc.blocks if b.header.startswith("interface ")]


def test_blank_and_comment_lines_are_not_counted_as_coverage_denominator():
    doc = ConfigDocument("hostname R1\n!\n\n!\ninterface Gi0/0\n")
    assert doc.significant_lines == 2


def test_acknowledged_lines_do_not_inflate_modelled_coverage():
    """Recognising a command is not the same as modelling it, and the coverage
    figure must not blur the two."""
    doc = ConfigDocument("hostname R1\nservice timestamps debug\n")
    doc.consume(doc.blocks[0])
    doc.acknowledge(doc.blocks[1])
    assert doc.coverage() == 0.5
    assert doc.accounted() == 1.0
    assert doc.unconsumed() == []


def test_unconsumed_reports_genuinely_unknown_lines():
    doc = ConfigDocument("hostname R1\nsome-unknown-command foo\n")
    doc.consume(doc.blocks[0])
    assert [line for _, line in doc.unconsumed()] == ["some-unknown-command foo"]
