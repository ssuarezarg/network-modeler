import yaml

from netconfig_mirror.analysis import (
    DANGLING,
    EMPTY,
    ORPHANED,
    audit,
    compare_policy,
    find_device,
    load_devices,
    render_audit,
    render_comparison,
    unacknowledged_dangling,
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
    """The case this was built for: Site_Alpha_in_in on one device and
    Site_Alpha_in on the other."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("Site_Alpha_in_in", ["10.0.0.0/8"])]},
        "r2": {"device": {"hostname": "r2"},
               "prefix_lists": [_pl("Site_Alpha_in", ["10.0.0.0/8"])]},
    })
    assert compare_policy(devices[0], devices[1]).possible_typos == \
        [("Site_Alpha_in_in", "Site_Alpha_in")]


def test_genuinely_different_names_are_not_called_typos(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"}, "prefix_lists": [_pl("CARRIER_OUT", ["10.0.0.0/8"])]},
        "r2": {"device": {"hostname": "r2"}, "prefix_lists": [_pl("CUSTOMER_IN", ["10.0.0.0/8"])]},
    })
    assert compare_policy(devices[0], devices[1]).possible_typos == []


def test_a_route_map_matching_a_nonexistent_list_is_found(tmp_path):
    """The dangerous one. A route-map matching a name that does not exist does
    not fail — it matches nothing, and the intended policy never applies."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("Site_Alpha_in_in", ["10.0.0.0/8"])],
               "route_maps": [{"name": "TO-CARRIER", "prefix_lists": ["Site_Alpha_in"]}]},
    })
    findings = [f for f in audit(devices) if f.kind == DANGLING]
    assert len(findings) == 1
    assert "route-map TO-CARRIER uses Site_Alpha_in" in findings[0].detail
    assert "did you mean Site_Alpha_in_in?" in findings[0].detail


def test_a_neighbour_applying_a_nonexistent_list_is_also_found(tmp_path):
    """On these edge routers, applying a prefix-list straight to a neighbour is
    the more common shape than going through a route-map."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("CUST_IN", ["10.0.0.0/8"])],
               "bgp": {"neighbors": [{"peer": "1.2.3.4",
                                      "prefix_lists": ["CUST_OUT out"]}]}},
    })
    findings = [f for f in audit(devices) if f.kind == DANGLING]
    assert "neighbor 1.2.3.4 uses CUST_OUT" in findings[0].detail


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


def test_two_directories_with_the_same_hostname_are_not_merged(tmp_path):
    """The phantom `Kernel` devices hold copies of the UK-CLL switch configs, so
    their parsed hostname is that of the real switch. Grouping a report by
    hostname merged them and listed every finding twice."""
    (tmp_path / "inventory" / "cll" / "uk-cll-l3-sw1").mkdir(parents=True)
    (tmp_path / "inventory" / "cll" / "kernel-2da233ff").mkdir(parents=True)
    doc = {"device": {"hostname": "UK-CLL-L3-SW1"},
           "prefix_lists": [_pl("UNUSED", ["10.0.0.0/8"])]}
    for name in ("uk-cll-l3-sw1", "kernel-2da233ff"):
        (tmp_path / "inventory" / "cll" / name / "device.yaml").write_text(
            yaml.safe_dump(doc), encoding="utf-8")

    devices = load_devices(tmp_path)
    out = render_audit(audit(devices), devices, full=True)

    assert out.count("kernel-2da233ff") >= 1
    assert out.count("uk-cll-l3-sw1") >= 1
    # One entry per directory, not both collapsed under one heading.
    assert out.count("UNUSED (1 entries)") == 2


def test_long_orphan_lists_are_sampled_unless_full_is_asked_for(tmp_path):
    many = [_pl(f"L{i}", ["10.0.0.0/8"]) for i in range(20)]
    devices = _mirror(tmp_path, {"r1": {"device": {"hostname": "r1"},
                                        "prefix_lists": many}})
    sampled = render_audit(audit(devices), devices)
    assert "and 12 more" in sampled
    assert "--full" in sampled
    assert "and 12 more" not in render_audit(audit(devices), devices, full=True)


def test_the_report_warns_that_a_dangling_name_may_be_a_parser_gap(tmp_path):
    """A name can appear dangling because this parser failed to recognise the
    definition — a fault here, not on the device. Saying so keeps the report
    from being taken to a customer as a misconfiguration."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]}]},
    })
    out = render_audit(audit(devices), devices)
    assert "raw.cfg" in out and "parser" in out


def test_a_finding_key_ignores_the_suggestion_text(tmp_path):
    """The key is built from the structural parts, never from the rendered
    sentence: the "did you mean …?" hint changes as the device changes, and an
    acknowledgement keyed on it would silently stop matching."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("Site_Alpha_in_in", ["10.0.0.0/8"])],
               "route_maps": [{"name": "RM", "prefix_lists": ["Site_Alpha_in"]}]},
    })
    finding = [f for f in audit(devices) if f.kind == DANGLING][0]
    # Keyed on the mirror path, which is unique; the hostname form stays valid
    # as the coarser match for files written before paths were used.
    assert finding.key == "dangling:dc4/r1:route-map RM:Site_Alpha_in"
    # The hostname form stays valid as the coarser match, so acknowledgement
    # files written before paths were used keep working.
    assert "dangling:r1:route-map RM:Site_Alpha_in" in finding.keys
    assert "did you mean" in finding.detail
    assert all("did you mean" not in k for k in finding.keys)


def test_an_acknowledged_finding_stays_in_the_report(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]}]},
    })
    key = "dangling:r1:route-map RM:MISSING"
    findings = audit(devices, {key})
    assert findings[0].acknowledged
    out = render_audit(findings, devices)
    assert "MISSING" in out and "acknowledged" in out


def test_only_unacknowledged_findings_drive_the_exit_code(tmp_path):
    """Twenty-seven known findings would otherwise fail every scheduled run from
    the first day, and a check that is always red is a check nobody reads."""
    from netconfig_mirror.analysis import unacknowledged_dangling

    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]},
                              {"name": "RM2", "prefix_lists": ["ALSO_MISSING"]}]},
    })
    findings = audit(devices, {"dangling:r1:route-map RM:MISSING"})
    outstanding = unacknowledged_dangling(findings)
    assert [f.target for f in outstanding] == ["ALSO_MISSING"]


def test_acknowledging_one_device_does_not_cover_the_same_name_elsewhere(tmp_path):
    """The key carries the hostname, so the same mistake on a second device is
    a separate finding — which is right: it needs fixing there too."""
    doc = {"route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]}]}
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"}, **doc},
        "r2": {"device": {"hostname": "r2"}, **doc},
    })
    from netconfig_mirror.analysis import unacknowledged_dangling

    findings = audit(devices, {"dangling:r1:route-map RM:MISSING"})
    assert [f.hostname for f in unacknowledged_dangling(findings)] == ["r2"]


def test_keys_are_generated_not_transcribed(tmp_path):
    """Hand-copying keys is how an acknowledgement silently stops matching: one
    wrong character and the finding alerts again with nothing to explain why.
    The key a finding reports must be exactly what acknowledges it."""
    from netconfig_mirror.analysis import unacknowledged_dangling

    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]}]},
    })
    key = unacknowledged_dangling(audit(devices))[0].key
    assert unacknowledged_dangling(audit(devices, {key})) == []


def test_two_devices_sharing_a_hostname_get_different_keys(tmp_path):
    """Hostnames are not unique in this estate: two devices are called
    EDGE-R1 and two more are called Kernel. Keyed on hostname they
    produce the same string, and acknowledging one silently acknowledges the
    other's finding too."""
    doc = {"device": {"hostname": "EDGE-R1"},
           "route_maps": [{"name": "BGP-to-OSPF", "prefix_lists": ["CORE-NETS"]}]}
    (tmp_path / "inventory" / "site1" / "edge-r1-21b484e9").mkdir(parents=True)
    (tmp_path / "inventory" / "site1" / "edge-r1-3b8259c4").mkdir(parents=True)
    for name in ("edge-r1-21b484e9", "edge-r1-3b8259c4"):
        (tmp_path / "inventory" / "site1" / name / "device.yaml").write_text(
            yaml.safe_dump(doc), encoding="utf-8")

    devices = load_devices(tmp_path)
    keys = [f.key for f in audit(devices) if f.kind == DANGLING]
    assert len(keys) == 2
    assert len(set(keys)) == 2


def test_acknowledging_one_of_a_shared_name_leaves_the_other_alerting(tmp_path):
    from netconfig_mirror.analysis import unacknowledged_dangling

    doc = {"device": {"hostname": "EDGE-R1"},
           "route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]}]}
    for name in ("a-21b484e9", "a-3b8259c4"):
        (tmp_path / "inventory" / "site1" / name).mkdir(parents=True)
        (tmp_path / "inventory" / "site1" / name / "device.yaml").write_text(
            yaml.safe_dump(doc), encoding="utf-8")

    devices = load_devices(tmp_path)
    first = audit(devices)[0].key
    assert len(unacknowledged_dangling(audit(devices, {first}))) == 1


def test_a_hostname_keyed_acknowledgement_still_works(tmp_path):
    """Files written before paths were used must keep working — and that form
    is deliberately coarser: it covers every device of that name."""
    from netconfig_mirror.analysis import unacknowledged_dangling

    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "route_maps": [{"name": "RM", "prefix_lists": ["MISSING"]}]},
    })
    assert unacknowledged_dangling(audit(devices, {"dangling:r1:route-map RM:MISSING"})) == []


def test_a_declared_but_empty_prefix_list_is_not_reported_as_missing(tmp_path):
    """An edge router in the estate carries `ip prefix-list TRANSIT-PREPEND
    description ...` and no entries. Reporting that as "does not exist" sends
    someone to create a list that is already there; the real question is where
    its entries went.
    """
    devices = _mirror(tmp_path, {
        "r1": {
            "device": {"hostname": "r1"},
            "prefix_lists": [{"name": "ASPrepend",
                              "description": "AS-Prepend transit routes",
                              "referenced_by": ["route-map OUT"]}],
            "route_maps": [{"name": "OUT", "prefix_lists": ["ASPrepend"]}],
        },
    })
    findings = audit(devices)

    assert [f.kind for f in findings if f.kind in (DANGLING, EMPTY)] == [EMPTY]
    empty = [f for f in findings if f.kind == EMPTY][0]
    assert "no entries" in empty.detail
    assert empty.key.startswith("empty:")


def test_an_empty_prefix_list_still_fails_the_audit(tmp_path):
    """Same effect on traffic as a missing one - the clause matches nothing -
    so it must not be quietly downgraded to a warning."""
    devices = _mirror(tmp_path, {
        "r1": {
            "device": {"hostname": "r1"},
            "prefix_lists": [{"name": "ASPrepend", "description": "d",
                              "referenced_by": ["route-map OUT"]}],
            "route_maps": [{"name": "OUT", "prefix_lists": ["ASPrepend"]}],
        },
    })
    assert unacknowledged_dangling(audit(devices))


def test_an_empty_prefix_list_can_be_acknowledged(tmp_path):
    devices = _mirror(tmp_path, {
        "r1": {
            "device": {"hostname": "r1"},
            "prefix_lists": [{"name": "ASPrepend", "description": "d",
                              "referenced_by": ["route-map OUT"]}],
            "route_maps": [{"name": "OUT", "prefix_lists": ["ASPrepend"]}],
        },
    })
    key = [f for f in audit(devices) if f.kind == EMPTY][0].key
    assert not unacknowledged_dangling(audit(devices, acknowledged={key}))


def _asa(tmp_path, doc):
    directory = tmp_path / "inventory" / "lac1" / "fw1"
    directory.mkdir(parents=True)
    (directory / "device.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return load_devices(tmp_path)


def test_a_crypto_map_matching_a_missing_access_list(tmp_path):
    """The same fault as a route-map matching a missing prefix-list, with a
    worse consequence: the clause matches no traffic, so the tunnel carries
    nothing while staying up and looking healthy."""
    devices = _asa(tmp_path, {
        "device": {"hostname": "fw1"},
        "vpn": {"crypto_maps": [{"name": "outside_map", "entries": [
            {"seq": "10", "match_address": "GONE", "peers": ["198.51.100.7"]}]}],
            "tunnel_groups": [{"name": "198.51.100.7",
                               "referenced_by": ["crypto map outside_map 10"]}]},
    })
    dangling = [f for f in audit(devices) if f.kind == DANGLING]

    assert len(dangling) == 1
    assert dangling[0].key == "dangling:lac1/fw1:crypto map outside_map 10:GONE"


def test_a_crypto_map_matching_an_empty_access_list(tmp_path):
    """A tunnel encrypting nothing."""
    devices = _asa(tmp_path, {
        "device": {"hostname": "fw1"},
        "access_lists": [{"name": "outside_cryptomap", "entry_count": 0}],
        "vpn": {"crypto_maps": [{"name": "outside_map", "entries": [
            {"seq": "10", "match_address": "outside_cryptomap"}]}]},
    })

    assert [f.kind for f in audit(devices) if f.kind in (DANGLING, EMPTY)] == [EMPTY]


def test_an_access_group_pointing_at_nothing(tmp_path):
    devices = _asa(tmp_path, {
        "device": {"hostname": "fw1"},
        "access_groups": [{"access_list": "GONE", "direction": "in",
                           "interface": "outside"}],
    })
    dangling = [f for f in audit(devices) if f.kind == DANGLING]

    assert dangling[0].target == "GONE"
    assert "access-group in outside" in dangling[0].source


def test_a_tunnel_group_nothing_points_at(tmp_path):
    devices = _asa(tmp_path, {
        "device": {"hostname": "fw1"},
        "vpn": {"tunnel_groups": [
            {"name": "198.51.100.7", "type": "ipsec-l2l",
             "referenced_by": ["crypto map outside_map 10"]},
            {"name": "198.51.100.99", "type": "ipsec-l2l"}]},
    })
    orphans = [f for f in audit(devices) if f.kind == ORPHANED]

    assert len(orphans) == 1
    assert orphans[0].target == "198.51.100.99"


def test_an_ipsec_profile_applied_to_no_interface(tmp_path):
    devices = _asa(tmp_path, {
        "device": {"hostname": "fw1"},
        "interfaces": [{"name": "Tunnel1", "tunnel_protection": "USED"}],
        "vpn": {"ipsec_profiles": [{"name": "USED",
                                    "referenced_by": ["interface Tunnel1"]},
                                   {"name": "UNUSED"}]},
    })
    orphans = [f for f in audit(devices) if f.kind == ORPHANED]

    assert [o.target for o in orphans] == ["UNUSED"]


def test_a_tunnel_interface_using_a_profile_that_does_not_exist(tmp_path):
    devices = _asa(tmp_path, {
        "device": {"hostname": "fw1"},
        "interfaces": [{"name": "Tunnel1", "tunnel_protection": "GONE"}],
        "vpn": {"ipsec_profiles": [{"name": "OTHER",
                                    "referenced_by": ["interface Tunnel1"]}]},
    })
    dangling = [f for f in audit(devices) if f.kind == DANGLING]

    assert dangling[0].target == "GONE"


def test_an_ios_device_produces_no_firewall_findings(tmp_path):
    """The firewall checks must stay silent on a platform that has none of
    these constructs, or they add a finding per device to every run."""
    devices = _mirror(tmp_path, {
        "r1": {"device": {"hostname": "r1"},
               "prefix_lists": [_pl("A", ["10.0.0.0/8"], referenced_by=["rm"])]},
    })

    assert audit(devices) == []
