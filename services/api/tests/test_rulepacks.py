"""The ready-made Suricata rule packs.

The rules themselves are validated by Suricata (`suricata -T`), not here --
this file pins the properties that Suricata would happily accept but that
would quietly make a pack useless in this stack:

* a rule with no `metadata: tag` produces only the generic `suricata` tag, so
  it never becomes a filter chip, which is the entire point of shipping them;
* a `drop` rule sneaking into a pack can take down our own service;
* duplicate sids would make "already installed?" undecidable.
"""

import pytest

import rulepacks
import rules


ALL = rulepacks.all_rules()


@pytest.fixture(autouse=True)
def rules_file(tmp_path, monkeypatch):
    """Per-test rules file, same reason as test_routes_rules: conftest's path
    is shared by the whole session, so without this an install in one test is
    still on disk for the next one."""
    monkeypatch.setattr(rules, "RULES_FILE", str(tmp_path / "suricata.rules"))


# --- catalog invariants ----------------------------------------------------

def test_every_rule_carries_a_tag_in_metadata():
    """`metadata: tag X` is the only metadata key the enricher reads."""
    for rule in ALL:
        assert f"metadata: tag {rule['tag']}" in rule["raw"], rule["sid"]


def test_no_pack_ships_a_drop_rule():
    """A misfiring drop takes down our own service, and if it catches the
    checker it bleeds SLA for as long as nobody notices. Blocking stays a
    deliberate per-rule decision made from /rules."""
    for rule in ALL:
        assert rule["raw"].startswith("alert "), rule["sid"]


def test_sids_are_unique_and_inside_the_reserved_block():
    sids = [r["sid"] for r in ALL]
    assert len(sids) == len(set(sids))
    for sid in sids:
        assert rulepacks.PACK_SID_MIN <= sid <= rulepacks.PACK_SID_MAX


def test_every_rule_pins_its_own_sid():
    """Installing has to be idempotent, which needs a stable sid rather than
    one auto-assigned at install time."""
    for rule in ALL:
        assert f"sid:{rule['sid']};" in rule["raw"]


def test_rules_avoid_the_stock_suricata_variables():
    """HOME_NET is Suricata's RFC1918 default here and HTTP_PORTS is only 80,
    so a rule using either would silently miss CTF services on odd ports."""
    for rule in ALL:
        assert "$HOME_NET" not in rule["raw"], rule["sid"]
        assert "$EXTERNAL_NET" not in rule["raw"], rule["sid"]
        assert "$HTTP_PORTS" not in rule["raw"], rule["sid"]


def test_every_rule_parses_with_the_rules_module():
    """The same parser the /rules table renders with."""
    for rule in ALL:
        parsed = rules.parse_one(rule["raw"])
        assert parsed is not None, rule["sid"]
        assert parsed.parsed is True, rule["sid"]
        assert parsed.sid == rule["sid"]
        assert parsed.action == "alert"


def test_pack_ids_are_unique_and_non_empty():
    ids = [p["id"] for p in rulepacks.PACKS]
    assert len(ids) == len(set(ids))
    for pack in rulepacks.PACKS:
        assert pack["rules"], pack["id"]
        assert pack["description"]


# --- catalog() -------------------------------------------------------------

def test_catalog_marks_nothing_installed_on_an_empty_file():
    cat = rulepacks.catalog(set())
    assert all(p["installed"] == 0 for p in cat)
    assert all(p["total"] == len(p["rules"]) for p in cat)


def test_catalog_counts_a_partial_install_honestly():
    """A pack the operator half-installed (or half-deleted) should say so
    rather than read as all-or-nothing."""
    first = rulepacks.PACKS[0]
    cat = rulepacks.catalog({first["rules"][0]["sid"]})
    got = next(p for p in cat if p["id"] == first["id"])
    assert got["installed"] == 1
    assert got["rules"][0]["installed"] is True
    assert got["rules"][1]["installed"] is False


# --- routes ----------------------------------------------------------------

def test_listing_packs_needs_only_a_session(viewer, anon):
    assert anon.get("/rules/packs").status_code == 401
    body = viewer.get("/rules/packs").get_json()
    assert {p["id"] for p in body["packs"]} == {p["id"] for p in rulepacks.PACKS}


def test_installing_requires_operator(viewer):
    assert viewer.post("/rules/packs/web-injection").status_code == 403


def test_unknown_pack_is_404(operator):
    assert operator.post("/rules/packs/nope").status_code == 404


def test_install_writes_the_rules(operator):
    pack = rulepacks.find_pack("web-injection")
    body = operator.post("/rules/packs/web-injection").get_json()
    assert len(body["added"]) == len(pack["rules"])
    assert body["skipped"] == 0
    assert "sqli" in body["tags"]

    on_disk = {r.sid for r in rules.load()}
    assert {r["sid"] for r in pack["rules"]} <= on_disk


def test_installing_twice_adds_nothing(operator):
    """Idempotent by sid, so a second click is harmless rather than a file
    full of duplicates."""
    operator.post("/rules/packs/web-injection")
    before = len(rules.load())
    body = operator.post("/rules/packs/web-injection").get_json()
    assert body["added"] == []
    assert body["skipped"] > 0
    assert len(rules.load()) == before


def test_noisy_rules_can_be_left_out(operator):
    pack = rulepacks.find_pack("web-injection")
    noisy = {r["sid"] for r in pack["rules"] if r.get("noisy")}
    assert noisy, "this test needs the pack to contain a noisy rule"

    operator.post("/rules/packs/web-injection", json={"include_noisy": False})
    on_disk = {r.sid for r in rules.load()}
    assert not (noisy & on_disk)


def test_install_is_audited(operator, monkeypatch):
    import audit
    logged = []
    monkeypatch.setattr(audit, "log", lambda *a, **kw: logged.append((a, kw)))
    operator.post("/rules/packs/recon")
    assert any(a[1] == "rules.pack_install" for a, _ in logged)


def test_a_pack_install_leaves_hand_written_rules_alone(operator):
    """add_many appends; it must not rewrite what is already in the file."""
    operator.post("/rules", json={"raw": 'alert ip any any -> any any (msg:"mine"; sid:9000123; rev:1;)'})
    operator.post("/rules/packs/exfil")
    sids = {r.sid for r in rules.load()}
    assert 9000123 in sids
