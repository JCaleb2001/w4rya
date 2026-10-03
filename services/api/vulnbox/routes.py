"""HTTP layer for the vulnbox module (Flask Blueprint, mounted at /vulnbox).

Routes stay thin: validate → call the module → audit. Authentication comes
from the app-wide before_request guard in webservice.py (Blueprint routes are
covered like any other); roles come from the same @auth.requires_role
decorator, and every gated route is listed in tests/test_routes_roles.py.

| route                              | role     |
|------------------------------------|----------|
| GET    /vulnbox                    | any      | overview: target, key, jobs, defaults
| POST   /vulnbox/key                | admin    | generate / rotate the keypair
| GET    /vulnbox/key/private        | admin    | download the private key (file only)
| DELETE /vulnbox/known-host         | admin    | forget the pinned host key
| POST   /vulnbox/preflight          | operator | background job
| POST   /vulnbox/recon              | operator | background job
| POST   /vulnbox/backup             | operator | background job
| POST   /vulnbox/import-services    | admin    | last recon → /config services
| POST   /vulnbox/seed-defaults      | admin    | ECSC 2026 values → /config
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, send_file

import app_config
import audit
import auth

from . import backup, config, jobs, keys, preflight, recon

bp = Blueprint("vulnbox", __name__, url_prefix="/vulnbox")


def _actor() -> str:
    return auth.current_user() or "?"


def _target() -> config.Target:
    """Resolve the SSH target from /config. Raises ValueError (→ 400)."""
    host = config.resolve_host(
        str(app_config.get("team_id") or ""),
        str(app_config.get("vulnbox_ip") or ""),
    )
    return config.Target(
        host=host,
        port=int(app_config.get("vulnbox_ssh_port") or 22),
        user=str(app_config.get("vulnbox_user") or "root"),
        services_path=str(app_config.get("vulnbox_services_path") or "/root/services"),
    )


def _job_running() -> bool:
    cur = jobs.snapshot()["current"]
    return bool(cur and cur.get("state") == "running")


def _busy_response():
    return jsonify({"error": "wait for the running vulnbox job to finish"}), 409


def _save_config(key: str, value) -> None:
    """Persist one /config value. Raises RuntimeError (→ 503) when the
    database is unavailable."""
    try:
        app_config.set(key, value)
    except Exception as e:
        raise RuntimeError(f"could not save {key}: {e}") from e


# --- overview ---------------------------------------------------------------

@bp.route("")
def overview():
    """Everything the page renders, in one poll. No private material."""
    try:
        t = _target()
        target = {"host": t.host, "port": t.port, "user": t.user,
                  "services_path": t.services_path, "error": None}
    except ValueError as e:
        target = {"host": None, "port": None, "user": None,
                  "services_path": None, "error": str(e)}
    defaults = config.ECSC2026_DEFAULTS
    return jsonify({
        "target": target,
        "key": keys.status(),
        "jobs": jobs.snapshot(),
        "defaults": {
            "values": defaults,
            "applied": all(app_config.get(k) == v for k, v in defaults.items()),
        },
    })


# --- key ----------------------------------------------------------------------

@bp.route("/key", methods=["POST"])
@auth.requires_role("admin")
def generate_key():
    body = request.get_json(silent=True) or {}
    rotate = bool(body.get("rotate"))
    if _job_running():
        return _busy_response()
    existed = keys.status().get("exists", False)
    try:
        status = keys.generate(rotate=rotate)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    audit.log(_actor(), "vulnbox.key_rotate" if existed else "vulnbox.key_generate",
              details={"fingerprint": status.get("fingerprint")})
    return jsonify(status), 201


@bp.route("/key/private")
@auth.requires_role("admin")
def download_private_key():
    """File download only — the private key never goes through a JSON body,
    so it never lands on a (recorded) screen by accident."""
    path = keys.private_key_path()
    if not path.exists():
        return jsonify({"error": "no key yet"}), 404
    audit.log(_actor(), "vulnbox.key_download")
    resp = send_file(str(path), as_attachment=True,
                     download_name="w4rya_vulnbox_ed25519",
                     mimetype="application/octet-stream", max_age=0)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/known-host", methods=["DELETE"])
@auth.requires_role("admin")
def forget_known_host():
    if _job_running():
        return _busy_response()
    removed = keys.forget_host_key()
    if removed:
        audit.log(_actor(), "vulnbox.forget_host_key")
    return jsonify({"removed": removed})


# --- background jobs ------------------------------------------------------------

def _start(kind: str, fn):
    try:
        target = _target()
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    try:
        record = jobs.start(kind, lambda: fn(target), actor=_actor())
    except jobs.JobBusy as e:
        return jsonify({"error": str(e), "running": e.kind}), 409
    audit.log(_actor(), f"vulnbox.{kind}", target=target.host)
    return jsonify(record), 202


@bp.route("/preflight", methods=["POST"])
@auth.requires_role("operator")
def run_preflight():
    return _start("preflight", lambda t: {"host": t.host, "checks": preflight.run(t)})


@bp.route("/recon", methods=["POST"])
@auth.requires_role("operator")
def run_recon():
    return _start("recon", lambda t: {"host": t.host, **recon.run(t)})


@bp.route("/backup", methods=["POST"])
@auth.requires_role("operator")
def run_backup():
    return _start("backup", lambda t: {"host": t.host, **backup.run(t)})


# --- /config writers ---------------------------------------------------------------

@bp.route("/import-services", methods=["POST"])
@auth.requires_role("admin")
def import_services():
    """Upsert the last recon's game services into /config → services."""
    last = jobs.snapshot()["last"].get("recon")
    if not last or last.get("state") != "done":
        return jsonify({"error": "run recon first"}), 409
    result = last["result"]
    imported = recon.to_config_services(result["services"], result["host"])
    if not imported:
        return jsonify({"error": "recon found no service publishing a port in "
                                 f"{config.GAME_PORT_MIN}-{config.GAME_PORT_MAX}"}), 400
    merged, added, updated = recon.merge_services(app_config.get("services") or [], imported)
    try:
        validated = [app_config.validate_service(e) for e in merged]
        _save_config("services", validated)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    audit.log(_actor(), "vulnbox.import_services",
              details={"added": added, "updated": updated})
    return jsonify({"services": validated, "added": added, "updated": updated})


@bp.route("/seed-defaults", methods=["POST"])
@auth.requires_role("admin")
def seed_defaults():
    """Apply the ECSC 2026 game values. The assembler reads the same settings
    from .env at boot, so the response also returns the .env lines to match."""
    applied = {}
    try:
        for key, raw in config.ECSC2026_DEFAULTS.items():
            value = app_config.coerce_scalar(key, raw)
            _save_config(key, value)
            applied[key] = value
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    audit.log(_actor(), "vulnbox.seed_defaults", details={"keys": sorted(applied)})
    env = {
        "FLAG_REGEX": applied["flag_regex"],
        "TICK_LENGTH": str(applied["tick_length"]),
        "TICK_START": applied["start_date"],
        "FLAG_LIFETIME": str(applied["flag_lifetime"]),
    }
    return jsonify({"applied": applied, "env": env})
