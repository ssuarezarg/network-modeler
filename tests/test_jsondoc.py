import json

from netconfig_mirror import jsondoc

KEY = b"test-key"


def test_rendering_is_canonical():
    """Two reads of the same policy can serialise with different key order and
    be the same policy. Without canonical rendering the diff means nothing."""
    a = jsondoc.render(json.loads('{"b": 1, "a": {"d": 2, "c": 3}}'))
    b = jsondoc.render(json.loads('{"a": {"c": 3, "d": 2}, "b": 1}'))
    assert a == b


def test_a_credential_named_field_is_redacted():
    """`"password": "hunter2"` matches none of the CLI rules. Without this,
    a third of the estate would have no fail-closed check at all."""
    obj, report = jsondoc.redact({"name": "rule1", "password": "hunter2"}, KEY)
    assert obj["password"].startswith("<redacted:")
    assert obj["name"] == "rule1"
    assert report.redacted == 1
    assert report.clean


def test_nested_and_listed_credentials_are_reached():
    obj, _ = jsondoc.redact(
        {"items": [{"snmpCommunity": "public"}, {"authKey": "abc123"}]}, KEY)
    assert obj["items"][0]["snmpCommunity"].startswith("<redacted:")
    assert obj["items"][1]["authKey"].startswith("<redacted:")


def test_similar_field_names_are_not_caught():
    """`keyword` and `publicKey` are not credentials; matching on a substring
    would redact half a firewall policy."""
    obj, report = jsondoc.redact({"keyword": "any", "publicKeyId": "abc"}, KEY)
    assert obj == {"keyword": "any", "publicKeyId": "abc"}
    assert report.redacted == 0


def test_the_same_secret_yields_the_same_token():
    first, _ = jsondoc.redact({"password": "x"}, KEY)
    second, _ = jsondoc.redact({"password": "x"}, KEY)
    assert first == second


def test_upstream_sanitised_values_are_left_alone():
    obj, report = jsondoc.redact({"password": "[OMITTED_BY_SANITIZER]"}, KEY)
    assert obj["password"] == "[OMITTED_BY_SANITIZER]"
    assert report.upstream_sanitised == 1


def test_audit_finds_an_unredacted_credential():
    assert jsondoc.audit_residuals({"cfg": {"password": "hunter2"}}) == ["cfg.password"]


def test_audit_accepts_a_redacted_one():
    obj, _ = jsondoc.redact({"cfg": {"password": "hunter2"}}, KEY)
    assert jsondoc.audit_residuals(obj) == []


def test_volatile_fields_are_discovered_by_comparing_two_captures():
    """The honest way to build the list: two captures with no configuration
    change between them, and see what moved. Guessing gives either a daily
    empty commit or a silently dropped field."""
    first = {"rules": [{"name": "allow", "hits": 10}], "metadata": {"timestamp": 1}}
    second = {"rules": [{"name": "allow", "hits": 47}], "metadata": {"timestamp": 2}}
    assert jsondoc.find_volatile(first, second) == ["metadata.timestamp", "rules[].hits"]


def test_nothing_moving_reports_nothing():
    same = {"rules": [{"name": "allow"}]}
    assert jsondoc.find_volatile(same, json.loads(json.dumps(same))) == []


def test_a_changed_list_length_is_reported_as_the_list():
    moved = jsondoc.find_volatile({"r": [1, 2]}, {"r": [1, 2, 3]})
    assert moved == ["r[] (length 2 vs 3)"]


def test_stripping_removes_only_the_named_paths():
    obj = jsondoc.strip_volatile(
        {"metadata": {"timestamp": 1, "author": "x"}, "rules": [{"name": "a"}]},
        paths=("metadata.timestamp",))
    assert obj == {"metadata": {"author": "x"}, "rules": [{"name": "a"}]}


def test_a_capture_that_is_not_json_is_recognised():
    assert jsondoc.parse("hostname R1\ninterface Gi0/0\n") is None
    assert jsondoc.parse('{"a": 1}') == {"a": 1}
