"""Tests for technique_map.py — the deterministic MITRE-ish classifier."""

from __future__ import annotations


def test_classify_exact_message_match():
    import technique_map
    out = technique_map.classify("SQLi union select")
    assert out["tactic"] == "Initial Access"
    assert out["mitre"] == "T1190"
    assert out["severity"] == "critical"


def test_classify_every_shipped_template_message_is_mapped():
    """Every message string rules.TEMPLATES ships must resolve to something
    more specific than the fallback default — a new template with no
    matching entry here would otherwise silently show up as "Unclassified"
    on the kill-chain view."""
    import re
    import rules
    import technique_map
    for tmpl in rules.TEMPLATES:
        m = re.search(r'msg:"([^"]+)"', tmpl["raw"])
        assert m, f"template has no msg: {tmpl['name']}"
        out = technique_map.classify(m.group(1))
        assert out["tactic"] != "Unknown", f"unmapped message: {m.group(1)!r}"


def test_classify_prefix_match_for_suggested_rules():
    import technique_map
    out = technique_map.classify("suggested: POST /api/signup on port 8008")
    assert out["technique"].startswith("Custom signature")
    out2 = technique_map.classify("suggested: raw payload match on port 5151")
    assert out2["tactic"] == "Unknown"


def test_classify_prefix_match_for_idor_variants():
    import technique_map
    assert technique_map.classify("IDOR: /api/sheets accessed via URL token instead of session cookie")["technique"].startswith("Broken Access Control")
    assert technique_map.classify("Possible IDOR: full route listing without ID (/api/route)")["technique"].startswith("Broken Access Control")


def test_classify_unknown_message_falls_back_to_default():
    import technique_map
    out = technique_map.classify("something a human typed by hand in /rules")
    assert out == {
        "tactic": "Unknown", "technique": "Unclassified signature",
        "mitre": None, "severity": "medium",
        "remediation": technique_map._HINT_GENERIC,
    }


def test_every_entry_carries_a_remediation_string():
    """The incident-packet endpoint always shows a remediation line — a
    classification with no hint would silently render blank there."""
    import technique_map
    for msg, rec in technique_map._BY_MESSAGE.items():
        assert rec.get("remediation"), f"{msg!r} has no remediation"
    for prefix, rec in technique_map._BY_PREFIX:
        assert rec.get("remediation"), f"{prefix!r} has no remediation"
    assert technique_map._DEFAULT.get("remediation")


def test_classify_new_exploit_technique_rules_are_mapped():
    """Rules added straight to suricata-rules/suricata.rules (not through
    rules.TEMPLATES) after the ExploitPcapCollection validation pass — these
    don't get caught by test_classify_every_shipped_template_message_is_mapped
    since that only walks TEMPLATES, so pin them here instead."""
    import technique_map
    for msg in (
        "Log4Shell JNDI lookup in URI",
        "ThinkPHP 5 RCE via invokefunction",
        "WebLogic console double-encoded traversal (CVE-2020-14882/14883)",
        "Fastjson autoType RCE (JdbcRowSetImpl gadget)",
        "Tomcat PUT JSP upload bypass (CVE-2017-12615)",
        "Apache Shiro rememberMe deserialization failure (CVE-2016-4437 indicator)",
        "SQLi error/blind injection function (extractvalue/updatexml/benchmark)",
        "SQLi INTO OUTFILE/DUMPFILE (webshell write via SQL)",
        "XXL-Job glueSource reverse shell payload",
        "MSSQL xp_cmdshell execution attempt (TDS)",
        "Nacos unauthenticated config removal (ops/data/removal)",
        "Possible NetBIOS name service scan (nbtscan-style recon)",
    ):
        assert technique_map.classify(msg)["tactic"] != "Unknown", f"unmapped: {msg!r}"


def test_classify_bruteforce_prefix_covers_every_port_variant():
    import technique_map
    for proto in ("SSH", "FTP", "Telnet", "SMB", "NetBIOS/SMB", "MSSQL", "MySQL",
                  "PostgreSQL", "Oracle DB", "Redis", "MongoDB", "RDP"):
        out = technique_map.classify(f"Possible brute force: repeated {proto} connection attempts")
        assert out["technique"] == "Brute Force"
        assert out["mitre"] == "T1110"


def test_classify_et_open_category_prefixes():
    import technique_map
    assert technique_map.classify("ET MALWARE Cobalt Strike Beacon Observed")["tactic"] == "Command and Control"
    assert technique_map.classify("ET EXPLOIT_KIT Something")["technique"].startswith("Drive-by")
    assert technique_map.classify("ET EXPLOIT Something not a kit")["tactic"] == "Initial Access"
    assert technique_map.classify("ET WEB_SPECIFIC_APPS Possible Oracle WebLogic RCE Inbound M4")["severity"] == "high"
    assert technique_map.classify("ET INFO SSH-2.0-Go version string Observed in Network Traffic")["severity"] == "low"
    assert technique_map.classify("ET SCAN Some scanner")["tactic"] == "Reconnaissance"


def test_classify_none_or_empty_falls_back_to_default():
    import technique_map
    assert technique_map.classify(None)["tactic"] == "Unknown"
    assert technique_map.classify("")["tactic"] == "Unknown"


def test_classify_returns_a_fresh_dict_each_time():
    """Callers may mutate the returned dict (e.g. to merge in extra fields);
    that must never corrupt the shared table."""
    import technique_map
    a = technique_map.classify("SQLi union select")
    a["severity"] = "mutated"
    b = technique_map.classify("SQLi union select")
    assert b["severity"] == "critical"


def test_summarize_picks_highest_severity_rule():
    import technique_map
    rules = [
        technique_map.classify("recon tool UA detected"),   # low
        technique_map.classify("SQLi union select"),         # critical
        technique_map.classify("path traversal"),            # medium
    ]
    tactic, severity = technique_map.summarize(rules)
    assert (tactic, severity) == ("Initial Access", "critical")


def test_summarize_empty_rules_with_flag_only():
    import technique_map
    assert technique_map.summarize([], has_flag_only=True) == ("Exfiltration", "high")


def test_summarize_empty_rules_no_flag():
    import technique_map
    assert technique_map.summarize([], has_flag_only=False) == ("Unknown", "medium")


def test_tactic_order_covers_every_tactic_used_in_the_table():
    import technique_map
    used = {v["tactic"] for v in technique_map._BY_MESSAGE.values()}
    used |= {v["tactic"] for _, v in technique_map._BY_PREFIX}
    used.add(technique_map._DEFAULT["tactic"])
    assert used <= set(technique_map.TACTIC_ORDER.keys())
