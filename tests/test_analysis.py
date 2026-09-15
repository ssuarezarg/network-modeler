import yaml

from netconfig_mirror.analysis import (
    DANGLING,
    ORPHANED,
    audit,
    compare_policy,
    find_device,
    load_devices,
    render_audit,
    render_comparison,
)


def _mirror(tmp_path, devices: dict[str, dict]):
    for name, doc in devices.items():
        directory = tmp_path / "inventory" / "dc4" / name
        directory.mkdir(parents=True)
        (directory / "device.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return load_devices(tmp_path)


def _pl(name, prefixes, referenced_by=None, start=5, step=5):
    return {
        "name": name,
        "entry_count": len(prefixes),
        "entries": [{"action": "permit", "prefix": p, "seq": str(start + i * step)}
                    for i, p in enumerate(prefixes)],
        "referenced_by": referenced_by or [],
    }


def test_identical_lists_are_reported_as_identical(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"}, "prefix_lists": [_pl("A", ["10.0.0.0/8"])]},
        "r2": {"device": {"hostname": "r2"}, "prefix_lists": [_pl("A", ["10.0.0.0/8"])]},
    })
    result = compare_policy(devices[0], devices[1])
    assert result.identical == ["A"]
    assert not result.differing


def test_same_entries_different_sequence_is_its_own_category(tmp_path):
    """Renumbering is usually equivalent and a different prefix never is.
    Collapsing them into "differs" would make the report cry wolf."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("A", ["10.0.0.0/8", "10.1.0.0/16"], start=5)]},
        "r2": {"device": {"hostname": "r2"},
               "prefix_lists": [_pl("A", ["10.1.0.0/16", "10.0.0.0/8"], start=100)]},
    })
    result = compare_policy(devices[0], devices[1])
    assert result.resequenced == ["A"]
    assert not result.differing


def test_a_different_prefix_is_reported_with_both_sides(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"}, "prefix_lists": [_pl("A", ["10.0.0.0/8"])]},
        "r2": {"device": {"hostname": "r2"}, "prefix_lists": [_pl("A", ["10.9.0.0/8"])]},
    })
    name, only_a, only_b = compare_policy(devices[0], devices[1]).differing[0]
    assert name == "A"
    assert only_a == ["permit 10.0.0.0/8"]
    assert only_b == ["permit 10.9.0.0/8"]


def test_a_doubled_suffix_is_flagged_as_a_probable_typo(tmp_path):
    """The case this was built for: BP_Plano_in_in on one device and
    BP_Plano_in on the other."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("BP_Plano_in_in", ["10.0.0.0/8"])]},
        "r2": {"device": {"hostname": "r2"},
               "prefix_lists": [_pl("BP_Plano_in", ["10.0.0.0/8"])]},
    })
    assert compare_policy(devices[0], devices[1]).possible_typos == \
        [("BP_Plano_in_in", "BP_Plano_in")]


def test_genuinely_different_names_are_not_called_typos(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"}, "prefix_lists": [_pl("LUMEN_OUT", ["10.0.0.0/8"])]},
        "r2": {"device": {"hostname": "r2"}, "prefix_lists": [_pl("CUSTOMER_IN", ["10.0.0.0/8"])]},
    })
    assert compare_policy(devices[0], devices[1]).possible_typos == []


def test_a_route_map_matching_a_nonexistent_list_is_found(tmp_path):
    """The dangerous one. A route-map matching a name that does not exist does
    not fail — it matches nothing, and the intended policy never applies."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("BP_Plano_in_in", ["10.0.0.0/8"])],
               "route_maps": [{"name": "TO-LUMEN", "prefix_lists": ["BP_Plano_in"]}]},
    })
    findings = [f for f in audit(devices) if f.kind == DANGLING]
    assert len(findings) == 1
    assert "TO-LUMEN matches BP_Plano_in" in findings[0].detail
    assert "did you mean BP_Plano_in_in?" in findings[0].detail


def test_an_unreferenced_list_is_reported_as_inert(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("USED", ["10.0.0.0/8"], referenced_by=["RM"]),
                                _pl("UNUSED", ["10.1.0.0/16"])]},
    })
    orphans = [f.detail for f in audit(devices) if f.kind == ORPHANED]
    assert orphans == ["UNUSED (1 entries)"]


def test_a_clean_estate_produces_no_findings(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("A", ["10.0.0.0/8"], referenced_by=["RM"])],
               "route_maps": [{"name": "RM", "prefix_lists": ["A"]}]},
    })
    assert audit(devices) == []
    assert "None." in render_audit([], devices)


def test_devices_are_found_by_hostname_or_by_path(tmp_path):
    devices = _mirror(tmp_path, {"dc4-edge-r1": {"device": {"hostname": "dc4-edge-r1"}}})
    assert find_device(devices, "dc4-edge-r1") is not None
    assert find_device(devices, "DC4-EDGE-R1") is not None
    assert find_device(devices, "nope-nothing") is None


def test_comparison_renders_without_a_device_yaml_key_missing(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"}},
        "r2": {"device": {"hostname": "r2"}},
    })
    out = render_comparison(devices[0], devices[1], compare_policy(devices[0], devices[1]))
    assert "r1 vs r2" in out
