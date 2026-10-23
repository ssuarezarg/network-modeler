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


ASA_SHAPED = """ASA Version 9.12(4)
hostname fw1
interface GigabitEthernet0/0
 nameif outside
 ip address 10.0.0.1 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
object network SRV-A
 host 10.1.1.10
object network SRV-B
 host 10.1.1.11
object network SRV-C
 host 10.1.1.12
object service HTTPS
 service tcp destination eq 443
access-list outside_in extended permit tcp any object SRV-A eq 443
access-list outside_in extended deny ip any any
access-list inside_in extended permit ip any any
"""


def _census(text):
    return {label: (count, nested)
            for label, count, nested in ConfigDocument(text).command_census()}


def test_a_closed_set_of_second_words_is_kept():
    """`object network` and `object service` are different things and a parser
    has to cover them separately, so the census must not merge them."""
    census = _census(ASA_SHAPED)

    assert census["object network"] == (3, 3)
    assert census["object service"] == (1, 1)


def test_an_identifier_as_second_word_is_collapsed():
    """An ACL name varies per line. Splitting on it would turn one command
    family worth thousands of lines into one row per access-list."""
    census = _census(ASA_SHAPED)

    assert census["access-list"] == (3, 0)
    assert not any(key.startswith("access-list ") for key in census)


def test_many_names_across_few_lines_collapse_too():
    """Two interfaces with two distinct names: as many names as lines, which is
    what an identifier looks like however small the sample."""
    census = _census(ASA_SHAPED)

    assert census["interface"] == (2, 3)


def test_nested_lines_are_counted_against_their_parent():
    """The weight of a block command is in its children, not its headers - the
    number that says how much of a parser it will take."""
    assert _census(ASA_SHAPED)["interface"][1] == 3


def test_a_command_seen_once_is_not_dressed_up_as_a_family():
    assert _census(ASA_SHAPED)["hostname"] == (1, 0)
