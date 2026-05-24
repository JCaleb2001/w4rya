#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Flower.
#
# Copyright ©2018 Nicolò Mazzucato
# Copyright ©2018 Antonio Groza
# Copyright ©2018 Brunello Simone
# Copyright ©2018 Alessio Marotta
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# Flower is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Flower is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Flower.  If not, see <https://www.gnu.org/licenses/>.

import dataclasses
import os
import re
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, send_file, jsonify, session
from requests import get
import dateutil.parser
from ipaddress import ip_network

from configurations import (
    services,
    traffic_dir,
    start_date,
    tick_length,
    visualizer_url,
    flag_lifetime,
    flag_regex,
    dump_pcaps_dir,
)
from pathlib import Path
from data2req import convert_flow_to_http_requests, convert_single_http_requests
from flask_cors import CORS
from flask import request

from flow2pwn import flow2pwn
import database, json_util
import auth
import app_config
import attack
import audit
import notes
import rules
import suricata_ctl

application = Flask(__name__)

_secret = os.environ.get("W4RYA_SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "W4RYA_SECRET_KEY env var is required (generate with: openssl rand -hex 32)"
    )
application.secret_key = _secret
application.config.update(
    SESSION_COOKIE_NAME="w4rya_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set true when behind HTTPS
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,  # 7 days
)

CORS(application, supports_credentials=True)
db = database.Pool(os.environ["TIMESCALE"])


@application.before_request
def _auth_guard():
    return auth.require_auth()


def return_json_response(object, **kwargs):
    return Response(json_util.dumps(object), mimetype="application/json", **kwargs)


def return_text_response(object, **kwargs):
    return Response(object, mimetype="text/plain", **kwargs)


@application.route("/")
def hello_world():
    return "Hello, World!"


@application.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if not auth.verify_password(username, password):
        audit.log(username or "?", "auth.login_fail")
        return jsonify({"error": "invalid credentials"}), 401
    session.clear()
    session["user"] = username
    session.permanent = True
    audit.log(username, "auth.login", details={"role": auth.current_role()})
    return jsonify({"user": username, "role": auth.current_role()})


@application.route("/logout", methods=["POST"])
def logout():
    who = auth.current_user()
    session.clear()
    if who:
        audit.log(who, "auth.logout")
    return jsonify({"ok": True})


@application.route("/me")
def me():
    return jsonify({
        "user": auth.current_user(),
        "role": auth.current_role(),
    })


@application.route("/tick_info")
def getTickInfo():
    data = {
        "startDate": app_config.get("start_date"),
        "tickLength": app_config.get("tick_length"),
        "flagLifetime": app_config.get("flag_lifetime"),
    }
    return return_json_response(data)


@application.route("/query", methods=["POST"])
def query():
    query = request.get_json()

    # Translate service_names -> list of (ip_network, port) pairs by looking
    # them up in the runtime services config. Frontend sends names so it
    # doesn't have to know the resolution rules.
    service_pairs: list[tuple] = []
    raw_names = query.get("service_names")
    requested_names = isinstance(raw_names, list) and len(raw_names) > 0
    if requested_names:
        cfg_services = app_config.get("services") or []
        by_name = {s["name"]: s for s in cfg_services if isinstance(s, dict)}
        for name in raw_names:
            svc = by_name.get(name)
            if not svc:
                continue
            try:
                service_pairs.append((ip_network(svc["ip"]), int(svc["port"])))
            except (KeyError, ValueError, TypeError):
                continue
    # Names were requested but NONE resolved -> return empty. Without this
    # we'd silently fall back to the unfiltered set, which is misleading
    # (e.g. a stale URL bookmark referencing a renamed service should show
    # nothing, not everything).
    if requested_names and not service_pairs:
        return return_json_response([])

    try:
        query = database.FlowQuery(
            regex_insensitive=(
                re.compile(query["regex_insensitive"])
                if "regex_insensitive" in query
                else None
            ),
            ip_src=ip_network(query["ip_src"]) if "ip_src" in query else None,
            ip_dst=ip_network(query["ip_dst"]) if "ip_dst" in query else None,
            port_src=query.get("port_src"),
            port_dst=query.get("port_dst"),
            services=service_pairs,
            time_from=(
                dateutil.parser.parse(query["time_from"])
                if "time_from" in query
                else None
            ),
            time_to=(
                dateutil.parser.parse(query["time_to"]) if "time_to" in query else None
            ),
            tags_include=[str(elem) for elem in query.get("tags_include", [])],
            tags_exclude=[str(elem) for elem in query.get("tags_exclude", [])],
            tag_intersection_and=query.get("tag_intersection_mode", "").lower() == "and",
        )
    except re.error as error:
        return return_json_response(
            {
                "error": str(error),
            },
            status=400,
        )

    with db.connection() as c:
        flows = c.flow_query(query)
    flows = list(map(dataclasses.asdict, flows))
    return return_json_response(flows)


@application.route("/stats")
def getStats():
    query = request.args

    query = database.StatsQuery(
        service=query.get("service"),
        tick_from=int(query["tick_from"]) if "tick_from" in query else None,
        tick_to=int(query["tick_to"]) if "tick_to" in query else None,
    )

    with db.connection() as c:
        stats = c.stats_query(query)
    stats = list(stats.values())
    return return_json_response(stats)


@application.route("/under_attack")
def getUnderAttack():
    vu = app_config.get("visualizer_url") or ""
    if not vu:
        return return_json_response({})
    res = get(
        f"{vu}/api/under-attack",
        params={
            "from_tick": request.args.get("from_tick"),
            "to_tick": request.args.get("to_tick"),
        },
    )
    assert res.status_code == 200

    tick_data = res.json()
    return return_json_response(tick_data)


@application.route("/tags")
def getTags():
    with db.connection() as c:
        tags = c.tag_list()
    return return_json_response(tags)


@application.route("/star", methods=["POST"])
@auth.requires_role("operator")
def setStar():
    query = request.get_json()
    flow_id = uuid.UUID(query.get("id"))
    apply = bool(query.get("star"))
    with db.connection() as c:
        c.flow_tag(flow_id, "starred", apply)
    return "ok!"


@application.route("/services")
def getServices():
    return return_json_response(app_config.get("services"))


@application.route("/attacks")
def attacks_timeline():
    """Chronological attack events (Suricata alerts + flag leaks).

    Filters: ?from_tick=N&to_tick=M&service=NAME&limit=K. All optional.
    Default window = last 10 ticks.
    """
    try:
        from_tick = request.args.get("from_tick", type=int)
        to_tick = request.args.get("to_tick", type=int)
        limit = int(request.args.get("limit", 200) or 200)
    except (TypeError, ValueError):
        return jsonify({"error": "bad numeric query param"}), 400
    limit = max(10, min(500, limit))
    service_filter = (request.args.get("service") or "").strip() or None

    tick_length_ms = int(app_config.get("tick_length") or 180000)
    try:
        tick_first = dateutil.parser.parse(app_config.get("start_date"))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid start_date in config"}), 500
    tick_length = timedelta(milliseconds=tick_length_ms)
    now = datetime.now(tz=timezone.utc)
    current_tick = int(((now - tick_first) // tick_length) + 1)
    if from_tick is None:
        from_tick = max(0, current_tick - 10)
    if to_tick is None:
        to_tick = current_tick + 1
    if to_tick <= from_tick:
        to_tick = from_tick + 1

    time_from = tick_first + (from_tick * tick_length)
    time_to = tick_first + (to_tick * tick_length)
    services_cfg = app_config.get("services") or []

    with db.connection() as c:
        events = c.attack_timeline(
            time_from, time_to, services_cfg, service_filter, limit
        )

    return return_json_response({
        "from_tick": from_tick,
        "to_tick": to_tick,
        "current_tick": current_tick,
        "tick_length_ms": tick_length_ms,
        "service": service_filter,
        "limit": limit,
        "count": len(events),
        "events": events,
    })


@application.route("/services/stats")
def get_services_stats():
    try:
        ticks = int(request.args.get("ticks", 5))
    except ValueError:
        ticks = 5
    ticks = max(1, min(50, ticks))
    tick_length_ms = int(app_config.get("tick_length") or 180000)
    services_cfg = app_config.get("services") or []

    now = datetime.now(tz=timezone.utc)
    time_start = now - timedelta(milliseconds=tick_length_ms * ticks)

    with db.connection() as c:
        rows = c.per_service_stats(time_start, services_cfg)

    return return_json_response({
        "ticks": ticks,
        "tick_length_ms": tick_length_ms,
        "from": time_start.isoformat(),
        "services": rows,
    })


@application.route("/flag_regex")
def getFlagRegex():
    return return_json_response(app_config.get("flag_regex"))


# --- /config (runtime-editable settings) -----------------------------------

def _config_payload() -> dict:
    return {k: app_config.get(k) for k in app_config.SCALAR_KEYS}


@application.route("/config")
def getConfig():
    return return_json_response(_config_payload())


@application.route("/config", methods=["PUT"])
@auth.requires_role("admin")
def putConfig():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "expected an object"}), 400
    errors = {}
    applied: list[str] = []
    for key, raw in data.items():
        if key not in app_config.SCALAR_KEYS:
            errors[key] = "unknown key"
            continue
        try:
            value = app_config.coerce_scalar(key, raw)
        except (TypeError, ValueError) as e:
            errors[key] = str(e)
            continue
        app_config.set(key, value)
        applied.append(key)
    if errors:
        return jsonify({"error": "invalid fields", "fields": errors}), 400
    audit.log(auth.current_user() or "?", "config.set", details={"keys": applied})
    return return_json_response(_config_payload())


@application.route("/config/services")
def getConfigServices():
    return return_json_response(app_config.get("services"))


@application.route("/config/services", methods=["PUT"])
@auth.requires_role("admin")
def putConfigServices():
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "expected a list"}), 400
    try:
        validated = [app_config.validate_service(e) for e in data]
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    app_config.set("services", validated)
    audit.log(auth.current_user() or "?", "config.services", details={"count": len(validated)})
    return return_json_response(validated)


@application.route("/config/teams")
def getConfigTeams():
    return return_json_response(app_config.get("teams"))


@application.route("/config/teams", methods=["PUT"])
@auth.requires_role("admin")
def putConfigTeams():
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "expected a list"}), 400
    try:
        validated = [app_config.validate_team(e) for e in data]
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    app_config.set("teams", validated)
    audit.log(auth.current_user() or "?", "config.teams", details={"count": len(validated)})
    return return_json_response(validated)


# --- /attack (exploit replay + script export) ------------------------------

@application.route("/attack/preview/<flow_id>")
def attack_preview(flow_id):
    """Cheap precheck shown in the Test-Exploit modal before firing."""
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return jsonify({"error": "invalid flow id"}), 400
    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404
    payload = attack.build_payload(flow)
    return return_json_response({
        "flow_id": str(flow.id),
        "port": int(flow.port_dst),
        "src_ip": str(flow.ip_src),
        "dst_ip": str(flow.ip_dst),
        "payload_size": len(payload),
        "client_items": sum(1 for i in flow.items if i.direction == "c" and i.kind == "raw"),
        "server_items": sum(1 for i in flow.items if i.direction == "s" and i.kind == "raw"),
    })


@application.route("/attack/replay", methods=["POST"])
@auth.requires_role("operator")
def attack_replay():
    body = request.get_json(silent=True) or {}
    raw_flow_id = body.get("flow_id") or ""
    try:
        fid = uuid.UUID(raw_flow_id)
    except (ValueError, TypeError):
        return jsonify({"error": "invalid flow id"}), 400

    targets_in = body.get("targets")
    if not isinstance(targets_in, list) or not targets_in:
        return jsonify({"error": "targets must be a non-empty list"}), 400

    targets: list[dict] = []
    for t in targets_in:
        if isinstance(t, str):
            targets.append({"name": t, "ip": t})
        elif isinstance(t, dict) and t.get("ip"):
            targets.append({
                "name": str(t.get("name") or t["ip"]),
                "ip": str(t["ip"]),
            })

    timeout = body.get("timeout")
    try:
        timeout = float(timeout) if timeout is not None else attack.DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        timeout = attack.DEFAULT_TIMEOUT

    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404

    result = attack.replay(flow, targets, timeout=timeout)
    audit.log(
        auth.current_user() or "?",
        "attack.replay",
        target=raw_flow_id,
        details={"target_count": len(targets), "timeout": timeout},
    )
    return return_json_response(result)


# --- /audit (admin-only log) -----------------------------------------------

@application.route("/audit")
@auth.requires_role("admin")
def audit_recent():
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    limit = max(10, min(1000, limit))
    rows = audit.recent(limit=limit)
    return return_json_response({"count": len(rows), "events": rows})


# --- /flow/<id>/notes ------------------------------------------------------

@application.route("/flow/<flow_id>/notes")
def list_flow_notes(flow_id):
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return jsonify({"error": "invalid flow id"}), 400
    items = [n.to_dict() for n in notes.list_for_flow(fid)]
    return return_json_response(items)


@application.route("/flow/<flow_id>/notes", methods=["POST"])
def add_flow_note(flow_id):
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return jsonify({"error": "invalid flow id"}), 400
    user = auth.current_user() or "anon"
    body = (request.get_json(silent=True) or {}).get("body", "")
    try:
        n = notes.add(fid, user, body)
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e)}), 400
    return return_json_response(n.to_dict())


@application.route("/notes/<note_id>", methods=["DELETE"])
def delete_flow_note(note_id):
    try:
        nid = uuid.UUID(note_id)
    except ValueError:
        return jsonify({"error": "invalid note id"}), 400
    user = auth.current_user() or ""
    err = notes.delete(nid, user)
    if err == "not_found":
        return jsonify({"error": "note not found"}), 404
    if err == "forbidden":
        return jsonify({"error": "only the author can delete"}), 403
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"ok": True})


# --- /rules (suricata rules CRUD) ------------------------------------------

def _maybe_autoreload() -> dict | None:
    """If rules_autoreload is on, trigger a suricata reload-rules.
    Returns suricata's response (or {error: ...}) for inclusion in the API
    response; never raises (we don't want a flaky socket to fail a save).

    Reads the toggle uncached so that a flip from another gunicorn worker is
    picked up on the next save (workers each hold a 5s per-key cache).
    """
    if not app_config.get_fresh("rules_autoreload"):
        return None
    try:
        return suricata_ctl.reload_rules()
    except FileNotFoundError as e:
        return {"error": str(e), "kind": "socket_missing"}
    except (OSError, ValueError) as e:
        return {"error": f"{type(e).__name__}: {e}", "kind": "socket_error"}


@application.route("/rules")
def list_rules():
    try:
        items = [r.to_dict() for r in rules.load()]
    except OSError as e:
        return jsonify({"error": f"rules file unreachable: {e}"}), 503
    return return_json_response({
        "file": rules.RULES_FILE,
        "rules": items,
        "templates": rules.TEMPLATES,
        "suricata": {
            "socket_available": suricata_ctl.available(),
            "autoreload": bool(app_config.get("rules_autoreload")),
        },
    })


@application.route("/rules", methods=["POST"])
@auth.requires_role("operator")
def add_rule():
    body = request.get_json(silent=True) or {}
    raw = (body.get("raw") or "").strip()
    enabled = bool(body.get("enabled", True))
    if not raw:
        return jsonify({"error": "raw rule text required"}), 400
    try:
        rule = rules.add(raw, enabled=enabled)
    except (ValueError, OSError) as e:
        return jsonify({"error": str(e)}), 400
    audit.log(auth.current_user() or "?", "rules.add", target=str(rule.sid))
    result = rule.to_dict()
    reload = _maybe_autoreload()
    if reload is not None:
        result["reload"] = reload
    return return_json_response(result)


@application.route("/rules/<int:sid>", methods=["PUT"])
@auth.requires_role("operator")
def update_rule(sid: int):
    body = request.get_json(silent=True) or {}
    raw = body.get("raw")
    enabled = body.get("enabled")
    try:
        rule = rules.update_one(
            sid,
            raw=raw if raw is not None else None,
            enabled=bool(enabled) if enabled is not None else None,
        )
    except (ValueError, OSError) as e:
        return jsonify({"error": str(e)}), 400
    if not rule:
        return jsonify({"error": "rule not found"}), 404
    audit.log(
        auth.current_user() or "?",
        "rules.update",
        target=str(sid),
        details={"enabled": rule.enabled, "raw_set": raw is not None},
    )
    result = rule.to_dict()
    reload = _maybe_autoreload()
    if reload is not None:
        result["reload"] = reload
    return return_json_response(result)


@application.route("/rules/<int:sid>", methods=["DELETE"])
@auth.requires_role("operator")
def delete_rule(sid: int):
    try:
        ok = rules.delete(sid)
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    if not ok:
        return jsonify({"error": "rule not found"}), 404
    audit.log(auth.current_user() or "?", "rules.delete", target=str(sid))
    out: dict = {"ok": True}
    reload = _maybe_autoreload()
    if reload is not None:
        out["reload"] = reload
    return jsonify(out)


@application.route("/rules/block-ip", methods=["POST"])
@auth.requires_role("operator")
def rules_block_ip():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    try:
        rule = rules.block_ip(ip)
    except (ValueError, OSError) as e:
        return jsonify({"error": str(e)}), 400
    audit.log(auth.current_user() or "?", "rules.block_ip", target=ip, details={"sid": rule.sid})
    result = rule.to_dict()
    reload = _maybe_autoreload()
    if reload is not None:
        result["reload"] = reload
    return return_json_response(result)


@application.route("/rules/reload", methods=["POST"])
@auth.requires_role("operator")
def reload_rules_route():
    try:
        result = suricata_ctl.reload_rules()
    except FileNotFoundError as e:
        return jsonify({"error": str(e), "kind": "socket_missing"}), 503
    except (OSError, ValueError) as e:
        return jsonify({"error": f"{type(e).__name__}: {e}", "kind": "socket_error"}), 502
    audit.log(auth.current_user() or "?", "suricata.reload")
    return jsonify(result)


@application.route("/attack/exploit-script/<flow_id>")
def attack_exploit_script(flow_id):
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return return_text_response("# error: invalid flow id"), 400
    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return return_text_response("# error: flow not found"), 404

    teams = app_config.get("teams") or []
    try:
        timeout = float(request.args.get("timeout", attack.DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = attack.DEFAULT_TIMEOUT
    script = attack.generate_script(flow, teams, timeout=timeout)
    return Response(
        script,
        mimetype="text/x-python",
        headers={
            "Content-Disposition": f'attachment; filename="w4rya_exploit_{flow_id}.py"'
        },
    )


@application.route("/flow/<id>")
def getFlowDetail(id):
    id = uuid.UUID(id)
    with db.connection() as c:
        flow = c.flow_detail(id)
    return return_json_response(flow)


@application.route("/to_single_python_request", methods=["POST"])
def convertToSingleRequest():
    flow_id = request.args.get("id", "")
    item_index = request.args.get("index", "")

    if flow_id == "":
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "No flow id", "No flow id param"
            )
        )
    if item_index == "":
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "No index", "No item index param"
            )
        )

    flow_id = uuid.UUID(flow_id)
    item_index = int(item_index)
    with db.connection() as c:
        flow = c.flow_detail(flow_id)
    if not flow:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid flow", "Invalid flow id"
            )
        )
    if item_index >= len(flow.items):
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid index", "Index out of range"
            )
        )

    tokenize = bool(request.args.get("tokenize", False))
    use_requests_session = bool(request.args.get("use_requests_session", False))
    try:
        converted = convert_single_http_requests(
            flow, item_index, tokenize, use_requests_session
        )
    except Exception as ex:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                type(ex).__name__, traceback.format_exc()
            )
        )
    return return_text_response(converted)


@application.route("/to_python_request/<id>")
def convertToRequests(id):
    id = uuid.UUID(id)
    with db.connection() as c:
        flow = c.flow_detail(id)
    if not flow:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid flow", "Invalid flow id"
            )
        )
    tokenize = bool(request.args.get("tokenize", True))
    use_requests_session = bool(request.args.get("use_requests_session", True))
    try:
        converted = convert_flow_to_http_requests(flow, tokenize, use_requests_session)
    except Exception as ex:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                type(ex).__name__, traceback.format_exc()
            )
        )
    return return_text_response(converted)


@application.route("/to_pwn/<id>")
def confertToPwn(id):
    id = uuid.UUID(id)
    with db.connection() as c:
        flow = c.flow_detail(id)
    if not flow:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid flow", "Invalid flow id"
            )
        )
    return return_text_response(flow2pwn(flow))


@application.route("/download/")
def downloadFile():
    filepath = request.args.get("file")
    if filepath is None:
        return return_text_response(
            "There was an error while downloading the requested file:\n{}: {}".format(
                "Invalid 'file'", "No 'file' given"
            )
        )
    filepath = Path(filepath)

    # Check for path traversal by resolving the file first.
    filepath = filepath.resolve()
    if traffic_dir not in filepath.parents and dump_pcaps_dir not in filepath.parents:
        return return_text_response(
            "There was an error while downloading the requested file:\n{}: {}".format(
                "Invalid 'file'",
                "'file' was not in a subdirectory of traffic_dir or dump_pcaps_dir",
            )
        )

    try:
        return send_file(filepath, as_attachment=True)
    except FileNotFoundError:
        return return_text_response(
            "There was an error while downloading the requested file:\n{}: {}".format(
                "Invalid 'file'", "'file' not found"
            )
        )

def create_app():
    db.open()
    app_config.set_pool(db)
    app_config.init_schema()
    notes.set_pool(db)
    notes.init_schema()
    audit.set_pool(db)
    audit.init_schema()
    return application

if __name__ == "__main__":
    try:
        db.open()
        application.run(host="0.0.0.0", threaded=True)
    finally:
        db.close()
