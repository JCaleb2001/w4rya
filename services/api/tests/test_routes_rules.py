"""Suricata rules CRUD over HTTP, against a real file on disk.

The file *is* the storage format — suricata reads the same bytes — so the
assertions here look at the text that landed on disk, not just at the JSON the
route echoed back.
"""

import pytest

import app_config
import rules

SIMPLE_RULE = 'alert tcp any any -> any any (msg:"w4rya test rule"; content:"pwn";)'


@pytest.fixture(autouse=True)
def rules_file(tmp_path, monkeypatch):
    """Per-test rules file.

    conftest already redirects W4RYA_RULES_FILE away from the real one, but
    that path is shared by the whole session: without this, a rule added by one
    test is still there for the next one.
    """
    path = tmp_path / "suricata.rules"
    monkeypatch.setattr(rules, "RULES_FILE", str(path))
    return path


class FakeSuricata:
    """Stands in for the module that talks to suricata's command socket."""

    def __init__(self, autoreload_result=None):
        self.calls: list[str] = []
        self._result = autoreload_result or {"return": "OK"}

    def available(self) -> bool:
        self.calls.append("available")
        return False

    def reload_rules(self) -> dict:
        self.calls.append("reload_rules")
        return self._result


@pytest.fixture(autouse=True)
def suricata(monkeypatch, webservice_mod):
    fake = FakeSuricata()
    monkeypatch.setattr(webservice_mod, "suricata_ctl", fake)
    return fake


def add_rule(client, raw=SIMPLE_RULE, **body):
    resp = client.post("/rules", json={"raw": raw, **body})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()


# --- GET -------------------------------------------------------------------

def test_get_rules_reports_an_empty_file_plus_templates_and_socket_status(operator):
    resp = operator.get("/rules")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["file"] == rules.RULES_FILE
    assert body["rules"] == []
    assert body["templates"] == rules.TEMPLATES
    assert body["suricata"] == {"socket_available": False, "autoreload": False}


def test_every_shipped_template_is_accepted_by_the_add_endpoint(operator):
    """The templates are one-click inserts in the UI; one that fails to parse
    would be a dead button."""
    for template in rules.TEMPLATES:
        rule = add_rule(operator, template["raw"])
        assert rule["parsed"] is True


# --- POST ------------------------------------------------------------------

def test_post_rules_auto_assigns_a_sid_in_the_reserved_range(operator, rules_file):
    """Auto sids start at 1,000,000 so they can never collide with the sids in
    a downloaded ruleset."""
    rule = add_rule(operator)
    assert rule["sid"] >= rules.AUTO_SID_START
    assert f"sid:{rule['sid']};" in rules_file.read_text()


def test_auto_assigned_sids_do_not_collide(operator):
    first = add_rule(operator)
    second = add_rule(operator, 'alert tcp any any -> any any (msg:"second";)')
    assert second["sid"] == first["sid"] + 1


def test_an_explicit_sid_in_the_rule_text_is_kept(operator):
    rule = add_rule(operator, 'alert tcp any any -> any any (msg:"pinned"; sid:4242; rev:1;)')
    assert rule["sid"] == 4242


def test_a_posted_rule_shows_up_in_the_listing_with_parsed_fields(operator):
    rule = add_rule(operator)
    listed = operator.get("/rules").get_json()["rules"]
    assert [r["sid"] for r in listed] == [rule["sid"]]
    assert listed[0]["parsed"] is True
    assert listed[0]["action"] == "alert"
    assert listed[0]["proto"] == "tcp"
    assert listed[0]["msg"] == "w4rya test rule"
    assert listed[0]["enabled"] is True


def test_post_rules_requires_non_empty_text(operator):
    resp = operator.post("/rules", json={"raw": "   "})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "raw rule text required"


def test_a_rule_with_unbalanced_parens_is_refused(operator, rules_file):
    """_inject_sid refuses to guess where the body ends; shifting rule
    semantics silently is worse than making the user type sid: themselves."""
    resp = operator.post("/rules", json={"raw": 'alert tcp any any -> any any (msg:"oops";'})
    assert resp.status_code == 400
    assert "unbalanced parens" in resp.get_json()["error"]
    assert not rules_file.exists()


def test_unparseable_text_is_stored_verbatim_rather_than_rejected(operator, rules_file):
    """Documented behaviour: the regex only understands the common rule shape,
    so anything else is kept as `raw` with parsed=false and shown to the user
    as-is. Suricata, not this parser, is the authority on validity."""
    rule = add_rule(operator, "this is not a suricata rule")
    assert rule["parsed"] is False
    assert rule["action"] is None
    assert rule["sid"] >= rules.AUTO_SID_START
    assert "this is not a suricata rule" in rules_file.read_text()
    assert operator.get("/rules").get_json()["rules"][0]["parsed"] is False


# --- PUT -------------------------------------------------------------------

def test_disabling_a_rule_writes_the_comment_prefix_to_disk(operator, rules_file):
    """'# ' is the suricata convention for a disabled rule; the file is what
    suricata reads, so the prefix has to be really there."""
    sid = add_rule(operator)["sid"]
    assert not rules_file.read_text().startswith("#")

    resp = operator.put(f"/rules/{sid}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is False

    line = rules_file.read_text().strip()
    assert line.startswith("# alert tcp")
    assert f"sid:{sid};" in line


def test_re_enabling_a_rule_strips_the_prefix_again(operator, rules_file):
    sid = add_rule(operator)["sid"]
    operator.put(f"/rules/{sid}", json={"enabled": False})
    resp = operator.put(f"/rules/{sid}", json={"enabled": True})
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is True
    assert rules_file.read_text().lstrip().startswith("alert tcp")


def test_a_disabled_rule_is_still_listed_as_a_rule(operator):
    sid = add_rule(operator)["sid"]
    operator.put(f"/rules/{sid}", json={"enabled": False})
    listed = operator.get("/rules").get_json()["rules"]
    assert [(r["sid"], r["enabled"]) for r in listed] == [(sid, False)]


def test_editing_the_raw_text_refreshes_the_derived_fields(operator):
    sid = add_rule(operator)["sid"]
    resp = operator.put(f"/rules/{sid}", json={
        "raw": f'drop udp any any -> any 53 (msg:"edited"; sid:{sid}; rev:2;)',
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert (body["action"], body["proto"], body["dport"]) == ("drop", "udp", "53")
    assert body["msg"] == "edited"
    assert body["sid"] == sid


def test_put_on_an_unknown_sid_is_a_404(operator):
    add_rule(operator)
    resp = operator.put("/rules/999", json={"enabled": False})
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "rule not found"


# --- DELETE ----------------------------------------------------------------

def test_delete_removes_the_rule_from_the_file(operator, rules_file):
    sid = add_rule(operator)["sid"]
    other = add_rule(operator, 'alert tcp any any -> any any (msg:"keep me";)')["sid"]

    resp = operator.delete(f"/rules/{sid}")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}

    text = rules_file.read_text()
    assert f"sid:{sid};" not in text
    assert f"sid:{other};" in text
    assert [r["sid"] for r in operator.get("/rules").get_json()["rules"]] == [other]


def test_delete_on_an_unknown_sid_is_a_404(operator):
    resp = operator.delete("/rules/999")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "rule not found"


# --- block-ip --------------------------------------------------------------

def test_block_ip_writes_a_drop_rule(operator, rules_file):
    resp = operator.post("/rules/block-ip", json={"ip": "10.6.6.6"})
    assert resp.status_code == 200
    rule = resp.get_json()
    assert rule["action"] == "drop"
    assert rule["src"] == "10.6.6.6"
    assert rule["enabled"] is True
    assert rule["sid"] >= rules.AUTO_SID_START

    text = rules_file.read_text()
    assert text.startswith("drop ip 10.6.6.6 any -> any any (")
    assert "w4rya:block:10.6.6.6@" in text
    assert "metadata: tag blocked" in text


@pytest.mark.parametrize("payload", [
    '1.2.3.4"; drop ip any any -> any any (msg:"pwned',
    "1.2.3.4; sid:1;",
    "1.2.3.4) (msg:\"x\"",
])
def test_block_ip_refuses_rule_syntax_injection(operator, rules_file, payload):
    """The ip goes into the rule text unquoted, so a `"`, `;`, `(` or `)` in it
    would let a caller append arbitrary suricata directives — including a
    `pass` rule that disables the team's whole ruleset."""
    resp = operator.post("/rules/block-ip", json={"ip": payload})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid ip"
    assert not rules_file.exists()


def test_block_ip_requires_an_ip(operator):
    resp = operator.post("/rules/block-ip", json={})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "ip required"


# --- autoreload ------------------------------------------------------------

def test_no_suricata_call_is_made_while_autoreload_is_off(operator, suricata):
    """rules_autoreload defaults to False, and a save must not touch the
    command socket then — the socket is usually absent, and the write path has
    to stay fast and independent of suricata being up."""
    sid = add_rule(operator)["sid"]
    operator.put(f"/rules/{sid}", json={"enabled": False})
    operator.post("/rules/block-ip", json={"ip": "10.6.6.7"})
    operator.delete(f"/rules/{sid}")

    assert "reload_rules" not in suricata.calls


def test_no_reload_field_is_attached_to_the_response_while_autoreload_is_off(operator):
    assert "reload" not in add_rule(operator)


def test_turning_autoreload_on_makes_every_save_reload_suricata(
    operator, suricata, monkeypatch
):
    """The toggle is read uncached (get_fresh) so a flip from another gunicorn
    worker takes effect on the next save rather than up to 5s later."""
    monkeypatch.setattr(app_config, "get_fresh", lambda key, default=None: True)
    result = add_rule(operator)
    assert result["reload"] == {"return": "OK"}
    assert suricata.calls.count("reload_rules") == 1
