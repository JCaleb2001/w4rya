"""Recon: parse the inventory, tie containers to service dirs, and turn the
result into /config services."""

import subprocess
from pathlib import Path

import pytest

import app_config
from vulnbox import config as vconfig
from vulnbox import keys, recon, ssh

TARGET = vconfig.Target(host="10.60.3.2", port=22, user="root", services_path="/root/services")

SAMPLE = "\n".join([
    "DIR\tnotes",
    "DIR\tshop",
    "DIR\tbad name;rm",
    "CTR\tnotes-web-1\t0.0.0.0:9001->80/tcp, :::9001->80/tcp\tnotes:latest\t/root/services/notes",
    "CTR\tnotes-db-1\t5432/tcp\tpostgres:16\t/root/services/notes",
    "CTR\tshop-app-1\t0.0.0.0:9100-9101->8000-8001/tcp\tshop:latest\t/root/services/shop/deploy",
    "CTR\tour-tool\t0.0.0.0:8080->8080/tcp\ttool:latest\t/opt/tool",
    "NOTE\tsomething informational",
]) + "\n"


def test_parse_and_build_maps_containers_by_compose_workdir():
    out = recon.build(recon.parse(SAMPLE), TARGET.services_path)
    svcs = {s["name"]: s for s in out["services"]}
    assert set(svcs) == {"notes", "shop"}  # the hostile name is dropped
    assert svcs["notes"]["game_ports"] == [9001]
    assert len(svcs["notes"]["containers"]) == 2
    # nested compose dir (.../shop/deploy) still belongs to shop; a range expands
    assert svcs["shop"]["game_ports"] == [9100, 9101]


def test_unsafe_name_and_unmatched_containers_become_notes():
    out = recon.build(recon.parse(SAMPLE), TARGET.services_path)
    notes = " ".join(out["notes"])
    assert "unsafe" in notes
    assert "our-tool" in notes          # running, but not under services path
    assert "something informational" in notes


def test_non_game_ports_are_kept_but_not_game_ports():
    out = recon.build(recon.parse(
        "DIR\tapi\nCTR\tapi-1\t0.0.0.0:8443->443/tcp\tapi:1\t/root/services/api\n"
    ), TARGET.services_path)
    svc = out["services"][0]
    assert svc["ports"] == [8443]
    assert svc["game_ports"] == []


def test_port_range_expansion_is_capped():
    out = recon.build(recon.parse(
        "DIR\tx\nCTR\tx-1\t0.0.0.0:9000-9999->9000-9999/tcp\tx:1\t/root/services/x\n"
    ), TARGET.services_path)
    assert len(out["services"][0]["ports"]) <= recon.MAX_RANGE_PORTS


def test_to_config_services_is_valid_config():
    out = recon.build(recon.parse(SAMPLE), TARGET.services_path)
    entries = recon.to_config_services(out["services"], TARGET.host)
    assert {(e["name"], e["port"]) for e in entries} == {("notes", 9001), ("shop", 9100), ("shop", 9101)}
    for e in entries:
        assert app_config.validate_service(e) == e  # round-trips the existing validator
        assert e["ip"] == "10.60.3.2"


def test_merge_replaces_same_ip_port_and_keeps_others():
    existing = [
        {"name": "old", "ip": "10.60.3.2", "port": 9001, "notes": ""},
        {"name": "manual", "ip": "10.60.3.2", "port": 9500, "notes": "keep me"},
    ]
    imported = [
        {"name": "notes", "ip": "10.60.3.2", "port": 9001, "notes": "imported from recon"},
        {"name": "shop", "ip": "10.60.3.2", "port": 9100, "notes": "imported from recon"},
    ]
    merged, added, updated = recon.merge_services(existing, imported)
    by_port = {e["port"]: e for e in merged}
    assert by_port[9001]["name"] == "notes"   # replaced
    assert by_port[9500]["name"] == "manual"  # untouched
    assert by_port[9100]["name"] == "shop"    # appended
    assert (added, updated) == (1, 1)


def test_run_without_key_errors_without_ssh(vbox_dir, monkeypatch):
    monkeypatch.setattr(ssh, "run_remote_script", lambda *a, **k: pytest.fail("ssh used"))
    with pytest.raises(RuntimeError, match="key"):
        recon.run(TARGET)


def test_run_reports_ssh_failure(vbox_dir, monkeypatch):
    keys.generate()
    monkeypatch.setattr(
        ssh, "run_remote_script",
        lambda *a, **k: subprocess.CompletedProcess([], 255, "", "Connection timed out"),
    )
    with pytest.raises(RuntimeError, match="VPN"):
        recon.run(TARGET)


def test_recon_script_runs_for_real_locally(tmp_path):
    services = tmp_path / "services"
    (services / "alpha").mkdir(parents=True)
    (services / "beta").mkdir()
    script = Path(recon.__file__).parent / "remote" / "recon.sh"
    proc = subprocess.run(["bash", str(script), str(services)],
                          capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0
    out = recon.build(recon.parse(proc.stdout), str(services))
    assert {s["name"] for s in out["services"]} == {"alpha", "beta"}
