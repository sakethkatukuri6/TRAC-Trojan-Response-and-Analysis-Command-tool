from contract.tools.validate import LIVE_URL, RAW_DOTTED, semantic_errors
from m4_ioc.extractor import extract_iocs


def test_static_candidates_do_not_become_fabricated_beacons():
    result = extract_iocs(
        b"",
        {"entropy": 0, "embedded_urls": ["hxxp://evil[.]example/path"], "strings": {"interesting": []}},
        {"status": "skipped", "_static_capabilities": {}},
        {"sha256": "a" * 64, "md5": "b" * 32},
    )

    assert result["beacons"] == []
    assert any(item["type"] == "url" for item in result["items"])


# ---------------------------------------------------------------------------
# Regression helpers.
#
# Everything below is generated input only: no sample is executed and nothing
# touches the network. ``BS`` is spelled as chr(92) so a Windows path inside a
# test reads exactly like the token M2 would publish, without escape ambiguity.
# ---------------------------------------------------------------------------

BS = chr(92)

_LEGAL_SOURCES = {"static_strings", "dynamic", "dropped_file", "pcap", "zeek"}


def _winpath(*parts):
    """A backslash-joined token, e.g. _winpath("HKLM", "Software", "Run")."""
    return BS.join(parts)


def _unc(*parts):
    """A UNC share path: two leading backslashes then the components."""
    return 2 * BS + BS.join(parts)


def _extract(strings=(), embedded_urls=(), static_extra=None, dynamic=None, sample=None):
    """Run the extractor over generated M2/M3 output and return the IOC section."""
    static_result = {
        "entropy": 0,
        "embedded_urls": list(embedded_urls),
        "strings": {"interesting": list(strings)},
    }
    if static_extra:
        static_result.update(static_extra)
    return extract_iocs(
        b"",
        static_result,
        dynamic if dynamic is not None else {"status": "skipped", "_static_capabilities": {}},
        sample if sample is not None else {},
    )


def _values(result, itype):
    return {item["value"] for item in result["items"] if item["type"] == itype}


def _items(result, itype):
    return [item for item in result["items"] if item["type"] == itype]


def _one(result, itype, value):
    """The single indicator carrying ``value``, so an assertion can name its tier."""
    matches = [item for item in result["items"] if item["type"] == itype and item["value"] == value]
    assert len(matches) == 1, (itype, value, result["items"])
    return matches[0]


# ---------------------------------------------------------------------------
# Rule 2 in practice: registry keys
# ---------------------------------------------------------------------------


def test_registry_key_tokens_are_extracted_from_strings():
    long_form = _winpath("HKEY_LOCAL_MACHINE", "SOFTWARE", "Microsoft", "Windows NT", "CurrentVersion", "Winlogon")
    short_form = _winpath("HKCU", "Software", "Microsoft", "Windows", "CurrentVersion", "Run")

    result = _extract(strings=[long_form, short_form, _winpath("HKLM", "SOFTWARE", "Classes", ".exe")])

    assert _values(result, "registry_key") == {long_form, short_form, _winpath("HKLM", "SOFTWARE", "Classes", ".exe")}
    entry = _one(result, "registry_key", short_form)
    assert entry["source"] == "static_strings"
    assert entry["confidence"] == 0.75


def test_bare_registry_hive_root_is_not_an_indicator():
    result = _extract(
        strings=[
            "HKLM",
            "HKCU",
            "HKEY_LOCAL_MACHINE",
            "HKEY_CURRENT_USER",
            "HKLM" + BS,
            "compare the HKLM and HKCU hives for persistence",
        ]
    )

    assert result["items"] == []


# ---------------------------------------------------------------------------
# Rule 2 in practice: mutexes and named kernel objects
# ---------------------------------------------------------------------------


def test_global_named_object_is_extracted_as_mutex_token():
    result = _extract(strings=[BS + "Global" + BS + "Foo", "Global" + BS + "Bar",
                               BS + "Local" + BS + "Foo"])

    mutexes = _items(result, "mutex")
    # The scope is part of the object's identity: Global\Foo and Local\Foo are two
    # different kernel objects and must not dedupe onto each other.
    assert {item["value"] for item in mutexes} == {"Global" + BS + "Foo", "Global" + BS + "Bar",
                                                   "Local" + BS + "Foo"}
    for item in mutexes:
        assert item["source"] == "static_strings"
        assert item["confidence"] == 0.7
        # The leading backslash is normalised away and no surrounding prose is kept.
        assert not item["value"].startswith(BS)


def test_session_named_object_is_extracted_as_mutex_token():
    result = _extract(strings=[BS + "Sessions" + BS + "1" + BS + "BaseNamedObjects" + BS + "SensiniLock"])

    name = "Sessions" + BS + "1" + BS + "BaseNamedObjects" + BS + "SensiniLock"
    assert _values(result, "mutex") == {BS + name}
    assert _one(result, "mutex", BS + name)["confidence"] == 0.7


def test_a_call_expression_does_not_leak_its_closer_into_the_object_name():
    result = _extract(strings=["CreateMutexW(\\Global\\SensiniMutex)"])

    assert _values(result, "mutex") == {"Global" + BS + "SensiniMutex"}


def test_labeled_mutex_token_is_extracted_from_strings():
    result = _extract(strings=["ZombieMutex7", "AppMut3xLock"])

    assert _values(result, "mutex") == {"ZombieMutex7", "AppMut3xLock"}
    for name in ("ZombieMutex7", "AppMut3xLock"):
        entry = _one(result, "mutex", name)
        assert entry["source"] == "static_strings"
        # A word-shaped token is the weakest evidence in the module.
        assert entry["confidence"] == 0.5


def test_prose_mentioning_a_mutex_is_not_an_indicator():
    result = _extract(
        strings=[
            "the mutex protects the shared section during startup",
            "a global handle is used for the mutex before the payload runs",
        ]
    )

    assert result["items"] == []


def test_dynamic_mutexes_outrank_their_static_counterparts():
    result = _extract(
        strings=["Global" + BS + "StaticOnlyThing"],
        dynamic={
            "status": "done",
            "mutexes": ["Global\\RuntimeThing"],
            "registry_events": [{"target": _winpath("HKLM", "SOFTWARE", "Run", "Updater")}],
            "file_events": [{"target": _winpath("C:", "Users", "Public", "stage2.exe")}],
            "_static_capabilities": {},
        },
    )

    runtime = _one(result, "mutex", "Global\\RuntimeThing")
    assert runtime["source"] == "dynamic"
    assert runtime["confidence"] == 0.85
    assert _one(result, "mutex", "Global" + BS + "StaticOnlyThing")["confidence"] == 0.7

    key = _one(result, "registry_key", _winpath("HKLM", "SOFTWARE", "Run", "Updater"))
    assert (key["source"], key["confidence"]) == ("dynamic", 0.8)
    path = _one(result, "filepath", _winpath("C:", "Users", "Public", "stage2.exe"))
    assert (path["source"], path["confidence"]) == ("dynamic", 0.75)


# ---------------------------------------------------------------------------
# Rule 2 in practice: user agents, paths, shares
# ---------------------------------------------------------------------------


def test_user_agent_token_is_extracted_without_the_header_label():
    agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/68.0"
    result = _extract(strings=["User-Agent: " + agent])

    assert _values(result, "user_agent") == {agent}
    entry = _one(result, "user_agent", agent)
    assert entry["source"] == "static_strings"
    assert entry["confidence"] == 0.7
    assert "User-Agent" not in entry["value"]


def test_windows_filepath_token_is_extracted_from_strings():
    payload = _winpath("C:", "Users", "Public", "payload.exe")
    result = _extract(strings=[payload])

    assert _values(result, "filepath") == {payload}
    assert _one(result, "filepath", payload)["confidence"] == 0.5
    # A .exe name is a file, not a domain.
    assert result["items"] == [_one(result, "filepath", payload)]


def test_unc_share_token_is_extracted_from_strings():
    share = _unc("fileserver", "share", "drop.exe")
    admin_share = _unc("dc01.lan", "ADMIN$")
    result = _extract(strings=[share, admin_share])

    paths = _values(result, "filepath")
    assert share in paths
    assert admin_share in paths
    assert _one(result, "filepath", share)["confidence"] == 0.55
    assert _one(result, "filepath", admin_share)["confidence"] == 0.55


# ---------------------------------------------------------------------------
# Rule 1 in practice: parse first, defang last
# ---------------------------------------------------------------------------


def test_consecutive_single_digit_octets_are_fully_defanged():
    result = _extract(strings=["8.8.8.8", "192.0.2.10", "beacon to 198.51.100.3 now"])

    assert _values(result, "ip") == {"8[.]8[.]8[.]8", "192[.]0[.]2[.]10", "198[.]51[.]100[.]3"}
    # The contract's gate looks for a raw dot between two word characters; every
    # octet boundary must be bracketed, not just the last one.
    for value in _values(result, "ip"):
        assert "[.]" in value
        assert RAW_DOTTED.search(value) is None


def test_non_remote_ip_addresses_are_not_published():
    result = _extract(
        strings=[
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.5",
            "169.254.9.9",
            "240.0.0.1",
            "binding to 0.0.0.0 while the peer is 203.0.113.9",
        ]
    )

    assert _values(result, "ip") == {"203[.]0[.]113[.]9"}


def test_filename_shaped_strings_are_not_published_as_domains():
    result = _extract(
        strings=[
            "readme.txt",
            "kernel32.dll",
            "System.Windows",
            "app.manifest",
            "config.xml",
            "svc_host.log",
        ]
    )

    assert _values(result, "domain") == set()
    assert result["items"] == []


def test_domain_indicators_are_defanged_and_benign_hosts_skipped():
    result = _extract(
        strings=["c2.evil[.]com", "www.microsoft.com", "update.adobe.com", "dropzone.example"]
    )

    assert _values(result, "domain") == {"c2[.]evil[.]com", "dropzone[.]example"}
    assert _one(result, "domain", "c2[.]evil[.]com")["confidence"] == 0.6


def test_url_from_strings_is_defanged_and_its_host_promoted():
    result = _extract(strings=["hxxp://192.0.2.10/beacon", "hxxps://gate.c2.example[.]com/x"])

    urls = _values(result, "url")
    assert urls == {"hxxp://192[.]0[.]2[.]10/beacon", "hxxps://gate[.]c2[.]example[.]com/x"}
    for url in urls:
        assert LIVE_URL.search(url) is None

    # The host of a URL is an indicator of its own, ranked above a bare
    # domain-shaped substring.
    assert _one(result, "ip", "192[.]0[.]2[.]10")["confidence"] == 0.75
    assert _one(result, "domain", "gate[.]c2[.]example[.]com")["confidence"] == 0.75


def test_embedded_urls_and_sample_hashes_take_the_top_tiers():
    result = _extract(
        embedded_urls=["hxxp://c2.example[.]com/task"],
        sample={"sha256": "a" * 64, "md5": "b" * 32},
    )

    assert _one(result, "sha256", "a" * 64)["confidence"] == 1.0
    assert _one(result, "md5", "b" * 32)["confidence"] == 1.0
    assert _one(result, "url", "hxxp://c2[.]example[.]com/task")["confidence"] == 0.85


def test_every_item_records_source_and_confidence():
    result = _extract(
        strings=[
            _winpath("HKLM", "SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Run"),
            BS + "Global" + BS + "Foo",
            "ZombieMutex7",
            "User-Agent: curl/7.55.1",
            _unc("fs01", "public"),
            _winpath("C:", "Windows", "Temp", "a.exe"),
            "8.8.8.8 operator@dropzone[.]com c2.evil[.]com",
            "hxxp://beacon.example/x",
        ],
        embedded_urls=["hxxp://drop.example/payload"],
        dynamic={"status": "done", "mutexes": ["RuntimeThing"], "_static_capabilities": {}},
        sample={"sha256": "c" * 64},
    )

    assert result["items"]
    for item in result["items"]:
        assert set(item) == {"type", "value", "source", "confidence"}
        assert item["source"] in _LEGAL_SOURCES
        assert isinstance(item["confidence"], float)
        assert 0.0 <= item["confidence"] <= 1.0
        if item["type"] in ("domain", "ip"):
            assert RAW_DOTTED.search(item["value"]) is None
        if item["type"] == "url":
            assert LIVE_URL.search(item["value"]) is None


def test_confidence_values_differ_by_source_tier():
    result = _extract(
        strings=[
            "8.8.8.8",
            "c2.evil[.]com",
            "operator@dropzone[.]com",
            "Global" + BS + "StaticThing",
            "ZombieMutex7",
            _unc("fileserver", "share", "drop.exe"),
        ],
        dynamic={
            "status": "done",
            "mutexes": ["RuntimeThing"],
            "registry_events": [{"target": _winpath("HKLM", "SOFTWARE", "Run", "Updater")}],
            "_static_capabilities": {},
        },
        sample={"sha256": "d" * 64},
    )

    # One indicator per extraction path, so the published tiers can be compared
    # against each other. Ranking is what an analyst reads the field for: an
    # observed runtime object outranks the same name found as a string, which in
    # turn outranks a bare domain-shaped substring.
    tiers = {
        "sample_hash": _one(result, "sha256", "d" * 64)["confidence"],
        "dynamic_mutex": _one(result, "mutex", "RuntimeThing")["confidence"],
        "dynamic_registry": _one(result, "registry_key", _winpath("HKLM", "SOFTWARE", "Run", "Updater"))["confidence"],
        "ip_in_strings": _one(result, "ip", "8[.]8[.]8[.]8")["confidence"],
        "named_object_in_strings": _one(result, "mutex", "Global" + BS + "StaticThing")["confidence"],
        "email_in_strings": _one(result, "email", "operator@dropzone[.]com")["confidence"],
        "domain_in_strings": _one(result, "domain", "c2[.]evil[.]com")["confidence"],
        "unc_share_in_strings": _one(result, "filepath", _unc("fileserver", "share", "drop.exe"))["confidence"],
        "labeled_mutex_in_strings": _one(result, "mutex", "ZombieMutex7")["confidence"],
    }

    assert len(set(tiers.values())) == len(tiers), tiers
    assert tiers["sample_hash"] == max(tiers.values())
    assert tiers["labeled_mutex_in_strings"] == min(tiers.values())
    assert tiers["dynamic_mutex"] > tiers["named_object_in_strings"] > tiers["labeled_mutex_in_strings"]
    assert tiers["ip_in_strings"] > tiers["email_in_strings"] > tiers["domain_in_strings"]
    # The published ranking matches the table the module documents.
    assert tiers == {
        "sample_hash": 1.0,
        "dynamic_mutex": 0.85,
        "dynamic_registry": 0.8,
        "ip_in_strings": 0.75,
        "named_object_in_strings": 0.7,
        "email_in_strings": 0.65,
        "domain_in_strings": 0.6,
        "unc_share_in_strings": 0.55,
        "labeled_mutex_in_strings": 0.5,
    }


def test_beacons_stay_empty_when_static_capabilities_report_c2():
    # A static marker is not an observed beacon: nothing here measured a timer.
    result = _extract(
        strings=["hxxp://c2.example[.]com/beacon", "8.8.8.8"],
        dynamic={
            "status": "skipped",
            "_static_capabilities": {
                "c2_networking": {
                    "att_id": "T1071.001",
                    "tactic": "command-and-control",
                    "description": "Application-layer protocol capability",
                    "matches": ["internetopen", "getaddrinfo"],
                },
                "injection": {
                    "att_id": "T1055",
                    "tactic": "defense-evasion",
                    "description": "Process injection capability",
                    "matches": ["createremotethread"],
                },
            },
        },
    )

    assert result["beacons"] == []
    assert result["status"] == "done"
    assert _values(result, "url") == {"hxxp://c2[.]example[.]com/beacon"}


def test_result_passes_contract_semantic_gate():
    result = _extract(
        strings=[
            "8.8.8.8",
            "192.0.2.10",
            "c2.evil[.]com",
            "hxxp://beacon.example[.]com:8080/gate",
            "operator@dropzone[.]com",
            BS + "Global" + BS + "Foo",
            _winpath("HKLM", "SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Run"),
            _winpath("C:", "Users", "Public", "stage2.exe"),
            _unc("fileserver", "share", "drop.exe"),
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "readme.txt kernel32.dll",
        ],
        embedded_urls=["hxxp://drop.example/payload"],
        dynamic={
            "status": "done",
            "mutexes": ["RuntimeThing"],
            "registry_events": [{"target": _winpath("HKCU", "Software", "Run", "Updater")}],
            "_static_capabilities": {
                "c2_networking": {
                    "att_id": "T1071.001",
                    "tactic": "command-and-control",
                    "description": "Application-layer protocol capability",
                    "matches": ["internetopen"],
                }
            },
        },
        sample={"sha256": "e" * 64, "md5": "f" * 32},
    )

    assert result["items"]
    assert semantic_errors({"iocs": result}) == []


# ---------------------------------------------------------------------------
# ATT&CK mapping merges two evidence sources and stays silent without a basis
# ---------------------------------------------------------------------------


def test_attack_techniques_merge_and_dedupe_static_and_import_evidence():
    static_extra = {
        "pe": {
            "imports": [
                "kernel32.dll:CreateRemoteThread",
                "wininet.dll:InternetOpenA",
                "advapi32.dll:RegSetValueExW",
                "cryptbase.dll:CryptDecrypt",
                "kernel32.dll:ReadFile",
            ]
        }
    }
    dynamic = {
        "status": "skipped",
        "_static_capabilities": {
            "injection": {
                "att_id": "T1055",
                "tactic": "defense-evasion",
                "description": "Process injection capability",
                "matches": ["createremotethread"],
            },
            "c2_networking": {
                "att_id": "T1071.001",
                "tactic": "command-and-control",
                "description": "Application-layer protocol capability",
                "matches": ["internetopen"],
            },
        },
    }

    techniques = _extract(static_extra=static_extra, dynamic=dynamic)["attack_techniques"]

    ids = [entry["id"] for entry in techniques]
    assert sorted(ids) == ["T1055", "T1071.001", "T1547.001"]
    assert len(ids) == len(set(ids)), "technique ids must be published once each"

    by_id = {entry["id"]: entry for entry in techniques}
    assert by_id["T1055"]["tactic"] == "defense-evasion"
    # Named by both sources -> one entry carrying both evidences.
    assert "Static markers: createremotethread" in by_id["T1055"]["evidence"]
    assert "Imported APIs: kernel32.dll:CreateRemoteThread" in by_id["T1055"]["evidence"]
    assert by_id["T1071.001"]["tactic"] == "command-and-control"
    # Persistence came only from the import table.
    assert by_id["T1547.001"]["evidence"].startswith("Imported APIs:")

    # Cryptography and file I/O are descriptive groups: no accusation without a basis.
    joined = " ".join(entry["evidence"] for entry in techniques)
    assert "CryptDecrypt" not in joined
    assert "ReadFile" not in joined


def test_descriptive_only_import_groups_yield_no_technique():
    techniques = _extract(
        static_extra={"pe": {"imports": ["cryptbase.dll:CryptDecrypt", "kernel32.dll:ReadFile", "ntdll.dll:NtClose"]}}
    )["attack_techniques"]

    assert techniques == []


def test_high_entropy_pe_yields_t1027():
    techniques = _extract(static_extra={"entropy": 7.8})["attack_techniques"]

    assert [entry["id"] for entry in techniques] == ["T1027"]
    assert techniques[0]["tactic"] == "defense-evasion"
    assert "Entropy 7.80" in techniques[0]["evidence"]


# ---------------------------------------------------------------------------
# A token is cut out of a sentence, the sentence is not published
# ---------------------------------------------------------------------------


def test_prose_after_a_path_is_not_part_of_the_indicator():
    payload = _winpath("C:", "Users", "Public", "stage2.exe")
    result = _extract(strings=[payload + " was written at boot"])

    assert _values(result, "filepath") == {payload}


def test_prose_after_a_registry_key_is_not_part_of_the_indicator():
    key = _winpath("HKLM", "Software", "Microsoft", "Windows", "CurrentVersion", "Run")
    result = _extract(strings=[key + " key was created by the installer"])

    assert _values(result, "registry_key") == {key}


def test_a_space_inside_a_real_path_is_kept():
    # "Program Files" is one directory, not the start of a sentence.
    payload = _winpath("C:", "Program", "Files", "Contoso", "updater.exe")
    result = _extract(strings=[payload])

    assert _values(result, "filepath") == {payload}


def test_win32_mutex_apis_are_not_published_as_kernel_objects():
    # These names sit in almost every import table; treating them as indicators would
    # make every sample in the vault look like it carries a mutex.
    result = _extract(
        strings=[
            "CreateMutexW",
            "OpenMutexA",
            "ReleaseMutex",
            "CreateMutexExW",
            "kernel32.dll:CreateMutexW",
        ]
    )

    assert _values(result, "mutex") == set()


def test_a_named_object_is_published_once_even_when_its_bare_name_also_appears():
    result = _extract(strings=["CreateMutexW(" + BS + "Global" + BS + "SensiniMutex)"])

    assert _values(result, "mutex") == {"Global" + BS + "SensiniMutex"}


def test_a_bare_mutex_name_with_no_scoped_counterpart_is_still_published():
    result = _extract(strings=["Global" + BS + "Foo", "OtherMutex"])

    assert _values(result, "mutex") == {"Global" + BS + "Foo", "OtherMutex"}
