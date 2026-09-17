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

import csv
import dataclasses
import io
import json
import logging
import os
import re
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from flask import Flask, Response, send_file, jsonify, session
import requests
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
import decode
import exploits
import notes
import rate_limit
import rules
import suricata_ctl
import technique_map
import user_store

application = Flask(__name__)

_secret = os.environ.get("W4RYA_SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "W4RYA_SECRET_KEY env var is required (generate with: openssl rand -hex 32)"
    )
application.secret_key = _secret
_cookie_secure = os.environ.get("W4RYA_COOKIE_SECURE", "").lower() in (
    "1", "true", "yes", "on",
)
application.config.update(
    SESSION_COOKIE_NAME="w4rya_session",
    SESSION_COOKIE_HTTPONLY=True,
    # Lax is OK for our usage (no cross-site flows). Bump to Strict if you
    # never serve the UI from a different origin than the API.
    SESSION_COOKIE_SAMESITE="Lax",
    # MUST be True when running behind HTTPS — set W4RYA_COOKIE_SECURE=1 in
    # .env once you have a TLS terminator in front of the api.
    SESSION_COOKIE_SECURE=_cookie_secure,
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


@application.route("/healthz")
def healthz():
    """Liveness + minimal DB connectivity check. No auth required (this is
    what Docker/k8s healthchecks call). Returns 200 only when the api can
    reach Timescale.
    """
    try:
        with db.connection() as c:
            c.execute("SELECT 1")
        return jsonify({"ok": True, "db": "up"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 503


@application.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    # No accounts exist yet: this is a fresh install, not a failed login.
    # Answering 401 "invalid credentials" here is what used to strand people
    # on a login form that could never succeed. Deliberately does NOT record
    # a rate-limit failure — otherwise the installer locks out the very
    # username they are about to create.
    if auth.user_count() == 0:
        return jsonify({
            "error": "no accounts exist yet",
            "needs_setup": True,
        }), 409

    # D1: brute-force protection. Per-worker in-memory bucket; with 3 gunicorn
    # workers an attacker still only gets ~15 attempts in 5 min. Acceptable
    # for team-internal threat model. (Public deployment should move this to
    # a shared store.)
    remote_ip = request.remote_addr or "?"
    rl_key = f"{remote_ip}::{username}"
    if rate_limit.is_blocked(rl_key):
        retry = rate_limit.seconds_until_unblock(rl_key)
        audit.log(username or "?", "auth.login_blocked", details={"ip": remote_ip})
        return jsonify({
            "error": "too many attempts; try again later",
            "retry_after_sec": retry,
        }), 429

    if not auth.verify_password(username, password):
        count = rate_limit.record_failure(rl_key)
        audit.log(username or "?", "auth.login_fail", details={"ip": remote_ip, "attempt": count})
        return jsonify({"error": "invalid credentials"}), 401

    rate_limit.clear(rl_key)
    session.clear()
    session["user"] = username
    session.permanent = True
    audit.log(username, "auth.login", details={"role": auth.current_role(), "ip": remote_ip})
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


# --- first-run setup -------------------------------------------------------
# A fresh clone has no auth/users.yaml (it is gitignored), so there is nobody
# to log in as. These two routes are public by necessity; POST /setup closes
# itself permanently as soon as one account exists.

@application.route("/setup/status")
def setup_status():
    """Public. Whether this install still needs its first account."""
    return jsonify({"needs_setup": auth.user_count() == 0})


@application.route("/setup", methods=["POST"])
def setup_first_user():
    """Public, self-closing. Creates the first account and signs it in.

    The first user is always created as `admin`: `viewer` (the default for
    every later account) could not reach /config or /audit, which would leave
    the install unusable, and omitting the role entirely would rely on the
    legacy "no role means admin" fallback in auth.py. Be explicit instead.
    """
    remote_ip = request.remote_addr or "?"
    rl_key = f"setup::{remote_ip}"
    if rate_limit.is_blocked(
        rl_key,
        window=rate_limit.SETUP_WINDOW_SEC,
        max_fails=rate_limit.SETUP_MAX_FAILS,
    ):
        retry = rate_limit.seconds_until_unblock(
            rl_key,
            window=rate_limit.SETUP_WINDOW_SEC,
            max_fails=rate_limit.SETUP_MAX_FAILS,
        )
        return jsonify({
            "error": "too many attempts; try again later",
            "retry_after_sec": retry,
        }), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    try:
        # only_if_empty re-checks under the file lock, so two workers racing
        # on a fresh install cannot both create a first admin.
        created = user_store.create_user(
            username, password, "admin", only_if_empty=True
        )
    except user_store.UserStoreError as e:
        # Only a "setup already completed" answer counts against the bucket.
        # A rejected password is an honest typo, not abuse.
        if e.code == 409:
            rate_limit.record_failure(rl_key, window=rate_limit.SETUP_WINDOW_SEC)
            audit.log(username or "?", "setup.rejected",
                      details={"ip": remote_ip, "reason": e.message})
        return jsonify({"error": e.message}), e.code

    auth.invalidate_users_cache()
    rate_limit.clear(rl_key)
    session.clear()
    session["user"] = created["username"]
    session.permanent = True
    audit.log(created["username"], "setup.create_first_user",
              target=created["username"],
              details={"ip": remote_ip, "role": created["role"]})
    return jsonify({"user": created["username"], "role": created["role"]}), 201


# --- user administration (admin only) --------------------------------------

@application.route("/users", methods=["GET"])
@auth.requires_role("admin")
def users_list():
    return jsonify(user_store.list_users())


@application.route("/users", methods=["POST"])
@auth.requires_role("admin")
def users_create():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or user_store.VALID_ROLES[0]).strip()
    try:
        created = user_store.create_user(username, password, role)
    except user_store.UserStoreError as e:
        return jsonify({"error": e.message}), e.code
    auth.invalidate_users_cache()
    audit.log(auth.current_user(), "users.create", target=created["username"],
              details={"role": created["role"]})
    return jsonify(created), 201


@application.route("/users/<username>", methods=["DELETE"])
@auth.requires_role("admin")
def users_delete(username):
    if username == auth.current_user():
        return jsonify({"error": "refusing to delete the account you are signed in as"}), 409
    try:
        user_store.delete_user(username)
    except user_store.UserStoreError as e:
        return jsonify({"error": e.message}), e.code
    auth.invalidate_users_cache()
    audit.log(auth.current_user(), "users.delete", target=username)
    return jsonify({"ok": True})


@application.route("/users/<username>/role", methods=["PUT"])
@auth.requires_role("admin")
def users_set_role(username):
    data = request.get_json(silent=True) or {}
    try:
        updated = user_store.set_role(username, (data.get("role") or "").strip())
    except user_store.UserStoreError as e:
        return jsonify({"error": e.message}), e.code
    auth.invalidate_users_cache()
    audit.log(auth.current_user(), "users.set_role", target=username,
              details={"role": updated["role"]})
    return jsonify(updated)


@application.route("/users/<username>/password", methods=["PUT"])
@auth.requires_role("admin")
def users_set_password(username):
    data = request.get_json(silent=True) or {}
    try:
        user_store.set_password(username, data.get("password") or "")
    except user_store.UserStoreError as e:
        return jsonify({"error": e.message}), e.code
    auth.invalidate_users_cache()
    # Never log the password itself, only that it was rotated.
    audit.log(auth.current_user(), "users.set_password", target=username)
    return jsonify({"ok": True})


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
    # silent=True so a request without a JSON content-type is a 400 rather than
    # a 415 with an HTML body (fetchBaseQuery cannot parse HTML).
    query = request.get_json(silent=True)
    if not isinstance(query, dict):
        return jsonify({"error": "a JSON object body is required"}), 400

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
            pcap_name=(str(query["pcap_name"]).strip() or None) if query.get("pcap_name") else None,
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
    vu = (app_config.get("visualizer_url") or "").strip()
    if not vu:
        return return_json_response({})
    # D1: validate URL scheme to prevent SSRF via a typo'd config value
    # (e.g. file:// or gopher://). HTTP/HTTPS only.
    parsed = urlparse(vu)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return return_json_response({"error": "visualizer_url invalid"}), 400
    try:
        # D1: hard timeout so a wedged visualizer can't freeze a gunicorn
        # worker. allow_redirects=False so a redirect can't bounce us to a
        # different host quietly.
        res = requests.get(
            f"{vu}/api/under-attack",
            params={
                "from_tick": request.args.get("from_tick"),
                "to_tick": request.args.get("to_tick"),
            },
            timeout=3,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return return_json_response({"error": f"visualizer: {e}"}), 502
    if res.status_code != 200:
        return return_json_response({"error": f"visualizer http {res.status_code}"}), 502
    try:
        return return_json_response(res.json())
    except ValueError:
        return return_json_response({"error": "visualizer returned non-JSON"}), 502


@application.route("/tags")
def getTags():
    with db.connection() as c:
        tags = c.tag_list()
    return return_json_response(tags)


@application.route("/star", methods=["POST"])
@auth.requires_role("operator")
def setStar():
    # get_json() without silent=True raises 415 on a missing content-type, and
    # uuid.UUID(None) raises TypeError — both surfaced as a 500 with an HTML
    # body the frontend cannot parse. Validate instead.
    query = request.get_json(silent=True) or {}
    try:
        flow_id = uuid.UUID(str(query.get("id") or ""))
    except (ValueError, TypeError):
        return jsonify({"error": "a valid flow id is required"}), 400
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
    checker_ips = set(app_config.get("checker_ips") or [])

    with db.connection() as c:
        events = c.attack_timeline(
            time_from, time_to, services_cfg, service_filter, limit,
            exclude_ips=checker_ips,
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


@application.route("/checker/candidates")
def checker_candidates():
    """Suggests src_ips that look like the gameserver checker (regular
    per-tick cadence, full service coverage, no exploit signatures) — a
    ranked suggestion for a human to confirm via PUT /config/checker-ips,
    never an automatic exclusion. See checker_detect.py for the scoring.

    Filters: ?from_tick=N&to_tick=M&limit=K. Default window = last 60 ticks
    (wider than /attacks' default — periodicity needs enough samples).
    """
    try:
        from_tick = request.args.get("from_tick", type=int)
        to_tick = request.args.get("to_tick", type=int)
        limit = int(request.args.get("limit", 10) or 10)
    except (TypeError, ValueError):
        return jsonify({"error": "bad numeric query param"}), 400
    limit = max(1, min(50, limit))

    tick_length_ms = int(app_config.get("tick_length") or 180000)
    try:
        tick_first = dateutil.parser.parse(app_config.get("start_date"))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid start_date in config"}), 500
    tick_length = timedelta(milliseconds=tick_length_ms)
    now = datetime.now(tz=timezone.utc)
    current_tick = int(((now - tick_first) // tick_length) + 1)
    if from_tick is None:
        from_tick = max(0, current_tick - 60)
    if to_tick is None:
        to_tick = current_tick + 1
    if to_tick <= from_tick:
        to_tick = from_tick + 1

    time_from = tick_first + (from_tick * tick_length)
    time_to = tick_first + (to_tick * tick_length)
    services_cfg = app_config.get("services") or []
    checker_ips = set(app_config.get("checker_ips") or [])

    with db.connection() as c:
        candidates = c.checker_candidates(
            time_from, time_to,
            total_known_ports=len(services_cfg) or 1,
            exclude_ips=checker_ips,
            limit=limit,
        )

    return return_json_response({
        "from_tick": from_tick,
        "to_tick": to_tick,
        "current_tick": current_tick,
        "candidates": candidates,
    })


@application.route("/config/checker-ips")
def getConfigCheckerIps():
    return return_json_response(app_config.get("checker_ips") or [])


@application.route("/config/checker-ips", methods=["PUT"])
@auth.requires_role("admin")
def putConfigCheckerIps():
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "expected a list"}), 400
    try:
        validated = [app_config.validate_checker_ip(e) for e in data]
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    app_config.set("checker_ips", validated)
    audit.log(auth.current_user() or "?", "config.checker_ips", details={"count": len(validated)})
    return return_json_response(validated)


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
    src_ip = str(flow.ip_src)
    checker_ips = set(app_config.get("checker_ips") or [])
    return return_json_response({
        "flow_id": str(flow.id),
        "port": int(flow.port_dst),
        "src_ip": src_ip,
        "dst_ip": str(flow.ip_dst),
        # NAT/gateway IPs are common on an A/D network, and the checker's own
        # traffic can look identical to a real attacker's (same account/route
        # lifecycle) — flag it so an operator doesn't save/replay the
        # checker's own SLA behavior as if it were a stolen exploit.
        "src_ip_is_checker": src_ip in checker_ips,
        "payload_size": len(payload),
        "client_items": sum(1 for i in flow.items if i.direction == "c" and i.kind == "raw"),
        "server_items": sum(1 for i in flow.items if i.direction == "s" and i.kind == "raw"),
    })


@application.route("/attack/suggest-rule/<flow_id>")
def attack_suggest_rule(flow_id):
    """Draft a Suricata rule from this flow's client payload — a starting
    point for monitoring to review and POST to /rules, not an auto-add."""
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return jsonify({"error": "invalid flow id"}), 400
    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404
    return return_json_response(attack.suggest_rule(flow))


def _choose_signature(flow, sid_param: str | None):
    """Shared by /attack/incident and /attack/exploit-code: pick which of a
    flow's signature hits to act on. `flow.signatures` decodes straight off
    the jsonb column as plain dicts ({"id","message","action"}), not
    `Signature` dataclass instances — same as database.attack_timeline().

    Returns (chosen_dict_or_None, error_response_or_None); a non-None error
    means the caller should return it directly. No sid param and no
    signatures at all is not an error — chosen is just None (e.g. a pure
    flag-leak flow).
    """
    if sid_param:
        try:
            sid_want = int(sid_param)
        except ValueError:
            return None, (jsonify({"error": "sid must be an integer"}), 400)
        chosen = next((s for s in flow.signatures if s.get("id") == sid_want), None)
        if not chosen:
            return None, (jsonify({"error": "that sid did not fire on this flow"}), 404)
        return chosen, None
    if flow.signatures:
        chosen = max(
            flow.signatures,
            key=lambda s: technique_map.SEVERITY_ORDER.get(
                technique_map.classify(s.get("message"))["severity"], 0
            ),
        )
        return chosen, None
    return None, None


@application.route("/attack/incident/<flow_id>")
def attack_incident(flow_id):
    """Bundle everything the patching team needs to act on one alert into
    one response: technique + remediation hint, the decoded attacker
    payload, how often this exact (rule, source) pair has fired before, and
    — when isolation succeeds (see attack.find_exploit_item) — the specific
    endpoint and input (query param / body field / header) the exploit
    rides in, so the patching team knows exactly what to go audit without
    reading a raw payload dump. Closes the loop from "an alert fired" to a
    copy-pasteable incident report, instead of the monitoring team
    hand-assembling one from the Attacks timeline, FlowView and the decode
    panel separately.

    `?sid=` picks which signature hit to report on when a flow matched more
    than one rule; defaults to the highest-severity hit. No sid and no
    signatures at all still returns a packet (technique falls back to
    "Unknown"), since a pure flag-leak flow is still worth a report.
    """
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return jsonify({"error": "invalid flow id"}), 400
    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404

    chosen, err = _choose_signature(flow, request.args.get("sid"))
    if err:
        return err

    chosen_message = chosen.get("message") if chosen else None
    classification = technique_map.classify(chosen_message)
    payload = attack.build_payload(flow)
    decoded = decode.decode_item(payload) if payload else {"whole": [], "embedded": []}

    stats = {"first_seen": None, "last_seen": None, "occurrence_count": 0}
    if chosen:
        with db.connection() as c:
            stats = c.incident_stats(chosen.get("id"), str(flow.ip_src))

    # Endpoint + vulnerable-input pinpointing: only meaningful once we've
    # isolated to a bounded set of specific requests (see find_exploit_item)
    # — on a "full_flow" fallback we don't know which of several requests
    # the rule actually meant, so we'd be guessing at which item to inspect.
    endpoint = None
    vulnerable_inputs: list[dict] = []
    matched_item_count = None
    if chosen:
        item_index, basis = attack.find_exploit_item(flow, chosen.get("id"))
        if basis == "single_item" and item_index is not None:
            item_data = flow.items[item_index].data
            endpoint = attack.describe_endpoint(item_data)
            clauses = attack.rule_content_clauses(chosen.get("id"))
            if clauses:
                vulnerable_inputs = attack.locate_vulnerable_input(item_data, clauses)
        elif basis == "matched_items" and item_index:
            # Several genuinely distinct requests all matched the rule (a
            # multi-stage attack, e.g. MSSQL's "enable xp_cmdshell" then
            # "run xp_cmdshell") — report the union of what each one hits
            # rather than arbitrarily picking one and losing the rest.
            matched_item_count = len(item_index)
            clauses = attack.rule_content_clauses(chosen.get("id"))
            seen_locations = set()
            for idx in item_index:
                item_data = flow.items[idx].data
                if endpoint is None:
                    endpoint = attack.describe_endpoint(item_data)
                if clauses:
                    for v in attack.locate_vulnerable_input(item_data, clauses):
                        key = (v["buffer"], v["location"])
                        if key not in seen_locations:
                            seen_locations.add(key)
                            vulnerable_inputs.append(v)

    src_ip = str(flow.ip_src)
    dst_ip = str(flow.ip_dst)
    dst_port = int(flow.port_dst)

    text_lines = [
        f"=== w4rya incident packet -- flow {flow.id} ===",
        "Technique : " + classification["technique"]
        + (f" ({classification['mitre']})" if classification.get("mitre") else ""),
        f"Tactic    : {classification['tactic']}   Severity: {classification['severity']}",
        f"Rule      : {chosen_message or '(no signature -- flag leak only)'}",
        f"Source    : {src_ip}  ->  {dst_ip}:{dst_port}",
        f"First seen: {stats['first_seen'] or '-'}    Last seen: {stats['last_seen'] or '-'}"
        f"    Occurrences: {stats['occurrence_count']}",
    ]
    if matched_item_count:
        text_lines.append(
            f"Note      : rule matched {matched_item_count} distinct requests in this "
            "session (e.g. a multi-stage attack) -- endpoint/inputs below are the union of all of them"
        )
    if endpoint:
        text_lines.append(f"Endpoint  : {endpoint}")
    if vulnerable_inputs:
        text_lines.append("Vulnerable input(s):")
        for v in vulnerable_inputs:
            suffix = f' = "{v["value"]}"' if v["value"] is not None else ""
            text_lines.append(f'  - {v["location"]}{suffix}')
    text_lines += [
        "",
        "Remediation:",
        f"  {classification['remediation']}",
        "",
        f"Captured payload ({len(payload)} bytes):",
        payload[:2048].decode("latin-1", errors="replace"),
    ]

    return return_json_response({
        "flow_id": str(flow.id),
        "sid": chosen.get("id") if chosen else None,
        "rule_message": chosen_message,
        **classification,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "time": flow.time.isoformat(),
        **stats,
        "endpoint": endpoint,
        "vulnerable_inputs": vulnerable_inputs,
        "matched_item_count": matched_item_count,
        "payload_size": len(payload),
        "decoded_payload": decoded,
        "text_packet": "\n".join(text_lines),
    })


@application.route("/attack/exploit-code/<flow_id>")
def attack_exploit_code(flow_id):
    """The "📋 Copy Exploit" button: readable Python for the flow — isolated
    down to just the client item(s) that matched the firing rule when we
    can tell, instead of every request in the whole captured session
    (signup/signin/upload/... glued together, most of it irrelevant to the
    actual attack — see attack.find_exploit_item's docstring). Usually one
    item (`"basis": "single_item"`); occasionally a short list when several
    genuinely distinct requests both mattered, e.g. a two-stage attack
    (`"basis": "matched_items"`, see `attack.narrow_flow_to_items`). Falls
    back to the full flow, clearly labeled `"basis": "full_flow"`, only when
    isolation isn't possible at all (pcre/flowbit-only rule, zero matches,
    or no signature at all).

    Two code generators, picked by protocol (`"protocol"` in the response):
    `data2req.py`'s `requests`-based generator for HTTP flows, or a plain
    socket connect/send/recv script (`attack.raw_socket_snippet` /
    `flow2pwn`) for anything else — a bare-TCP CTF service (no HTTP
    framing) fed through the HTTP generator doesn't degrade, it raises
    (`.lower()` on the `None` method `BaseHTTPRequestHandler` leaves after
    failing to parse a non-HTTP request line). `is_http_request` gates
    which path runs so this endpoint always returns runnable code instead
    of a 500 the moment monitoring points it at a non-HTTP service.

    `?sid=` picks which signature hit to isolate around, same as
    /attack/incident; defaults to the highest-severity hit.
    """
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return jsonify({"error": "invalid flow id"}), 400
    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404

    chosen, err = _choose_signature(flow, request.args.get("sid"))
    if err:
        return err

    item_index, basis = attack.find_exploit_item(flow, chosen.get("id") if chosen else None)
    client_items = [it for it in flow.items if it.direction == "c" and it.kind == "raw"]

    try:
        if basis == "single_item" and item_index is not None:
            item_data = flow.items[item_index].data
            if attack.is_http_request(item_data):
                protocol = "http"
                code = convert_single_http_requests(flow, item_index, True, True)
            else:
                protocol = "raw"
                code = attack.raw_socket_snippet(item_data, int(flow.port_dst))
        elif basis == "matched_items" and item_index:
            # Several genuinely distinct requests all matched the rule —
            # narrow the flow to just those instead of falling all the way
            # back to every request in the session (see find_exploit_item).
            narrowed = attack.narrow_flow_to_items(flow, item_index)
            if all(attack.is_http_request(it.data) for it in narrowed.items):
                protocol = "http"
                code = convert_flow_to_http_requests(narrowed, True, True)
            else:
                protocol = "raw"
                code = flow2pwn(narrowed)
        elif client_items and all(attack.is_http_request(it.data) for it in client_items):
            protocol = "http"
            code = convert_flow_to_http_requests(flow, True, True)
        else:
            protocol = "raw"
            code = flow2pwn(flow)
    except Exception as ex:
        return jsonify({"error": f"could not generate exploit code: {ex}"}), 500

    # item_index is a position (or, for "matched_items", a list of
    # positions) in the FULL items array (client+server interleaved) —
    # convert to "request N of M" among client items only, which is what's
    # actually meaningful to show an operator.
    client_indices = [
        i for i, it in enumerate(flow.items) if it.direction == "c" and it.kind == "raw"
    ]
    client_ordinal = (
        client_indices.index(item_index) + 1
        if basis == "single_item" and item_index is not None and item_index in client_indices
        else None
    )
    matched_ordinals = (
        [client_indices.index(i) + 1 for i in item_index if i in client_indices]
        if basis == "matched_items" and item_index
        else None
    )

    return return_json_response({
        "flow_id": str(flow.id),
        "sid": chosen.get("id") if chosen else None,
        "basis": basis,
        "protocol": protocol,
        "item_index": item_index if basis == "single_item" else None,
        "client_ordinal": client_ordinal,
        "matched_ordinals": matched_ordinals,
        "client_item_count": len(client_indices),
        "code": code,
    })


def _parse_targets(targets_in) -> list[dict] | None:
    """Shared target-list parsing for every replay route. Accepts either a
    bare IP string or {"name","ip"} — the ad-hoc-target UI sends the latter
    with a name of the operator's choosing, same shape as a configured team."""
    if not isinstance(targets_in, list) or not targets_in:
        return None
    targets: list[dict] = []
    for t in targets_in:
        if isinstance(t, str):
            targets.append({"name": t, "ip": t})
        elif isinstance(t, dict) and t.get("ip"):
            targets.append({
                "name": str(t.get("name") or t["ip"]),
                "ip": str(t["ip"]),
            })
    return targets


def _parse_timeout(body: dict) -> float:
    timeout = body.get("timeout")
    try:
        return float(timeout) if timeout is not None else attack.DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        return attack.DEFAULT_TIMEOUT


def _parse_port_override(body: dict) -> int | None:
    """None means 'use the captured/saved port' — the normal case. Raises
    ValueError for a present-but-invalid port so the caller can 400."""
    port = body.get("port")
    if port is None or port == "":
        return None
    port = int(port)
    if not (0 < port < 65536):
        raise ValueError("port out of range")
    return port


def _parse_payload_override(body: dict) -> bytes | None:
    """The payload editor round-trips bytes through latin-1 text (a lossless
    1:1 mapping for 0-255), so an operator can eyeball/tweak an HTTP request
    without a hex editor. None means 'use the captured/saved payload'."""
    text = body.get("payload_text")
    if text is None:
        return None
    if not isinstance(text, str):
        raise ValueError("payload_text must be a string")
    return text.encode("latin-1", errors="replace")


@application.route("/attack/payload/<flow_id>")
def attack_payload(flow_id):
    """The raw client payload as editable text, for the send-exploit panel's
    payload editor — /attack/preview only gives sizes/counts, not bytes."""
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
        "payload_text": payload.decode("latin-1", errors="replace"),
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

    targets = _parse_targets(body.get("targets"))
    if targets is None:
        return jsonify({"error": "targets must be a non-empty list"}), 400
    timeout = _parse_timeout(body)
    try:
        port_override = _parse_port_override(body)
        payload_override = _parse_payload_override(body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404

    payload = payload_override if payload_override is not None else attack.build_payload(flow)
    port = port_override if port_override is not None else int(flow.port_dst)
    result = attack.replay_payload(
        payload, port, targets, timeout=timeout, result_id=str(flow.id),
        rewrite_host=(payload_override is None),
    )
    audit.log(
        auth.current_user() or "?",
        "attack.replay",
        target=raw_flow_id,
        details={
            "target_count": len(targets), "timeout": timeout,
            "port_overridden": port_override is not None,
            "payload_overridden": payload_override is not None,
        },
    )
    return return_json_response(result)


# --- /exploits (saved exploit library) --------------------------------------
#
# A flow captured once (attack.replay/exploit-script) is one-shot: find it
# again next tick to fire it again. Saving it here snapshots the client
# payload + port at save time, so the attack team builds a growing,
# named/tagged library instead of re-hunting the same flow every time they
# want to reuse a technique someone else on the team already found.

def _exploit_script_filename(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_")[:60]
    return slug or "exploit"


@application.route("/exploits")
def list_exploits():
    return return_json_response([e.to_dict() for e in exploits.list_all()])


@application.route("/exploits/<id>")
def get_exploit(id):
    """Single exploit with its payload as editable text — the send-exploit
    panel's payload editor fetches this before letting an operator tweak
    a saved exploit's bytes for one specific replay."""
    try:
        eid = uuid.UUID(id)
    except ValueError:
        return jsonify({"error": "invalid id"}), 400
    ex = exploits.get(eid)
    if not ex:
        return jsonify({"error": "not found"}), 404
    d = ex.to_dict()
    d["payload_text"] = ex.payload.decode("latin-1", errors="replace")
    return return_json_response(d)


@application.route("/exploits", methods=["POST"])
@auth.requires_role("operator")
def save_exploit():
    body = request.get_json(silent=True) or {}
    raw_flow_id = body.get("flow_id") or ""
    try:
        fid = uuid.UUID(raw_flow_id)
    except (ValueError, TypeError):
        return jsonify({"error": "invalid flow id"}), 400
    with db.connection() as c:
        flow = c.flow_detail(fid)
    if not flow:
        return jsonify({"error": "flow not found"}), 404

    try:
        port_override = _parse_port_override(body)
        payload_override = _parse_payload_override(body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    payload = payload_override if payload_override is not None else attack.build_payload(flow)
    port = port_override if port_override is not None else int(flow.port_dst)

    try:
        ex = exploits.save(
            name=str(body.get("name") or ""),
            tag=str(body.get("tag") or ""),
            source_flow_id=fid,
            port=port,
            payload=payload,
            created_by=auth.current_user() or "?",
            notes=str(body.get("notes") or ""),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    checker_ips = set(app_config.get("checker_ips") or [])
    audit.log(
        auth.current_user() or "?", "exploits.save",
        target=str(ex.id), details={
            "name": ex.name, "source_flow_id": raw_flow_id,
            "payload_edited": payload_override is not None,
            "source_ip_was_checker": str(flow.ip_src) in checker_ips,
        },
    )
    d = ex.to_dict()
    d["source_ip_was_checker"] = str(flow.ip_src) in checker_ips
    return return_json_response(d), 201


@application.route("/exploits/<id>", methods=["DELETE"])
@auth.requires_role("operator")
def delete_exploit(id):
    try:
        eid = uuid.UUID(id)
    except ValueError:
        return jsonify({"error": "invalid id"}), 400
    if not exploits.delete(eid):
        return jsonify({"error": "not found"}), 404
    audit.log(auth.current_user() or "?", "exploits.delete", target=id)
    return jsonify({"ok": True})


@application.route("/exploits/<id>/replay", methods=["POST"])
@auth.requires_role("operator")
def replay_exploit(id):
    try:
        eid = uuid.UUID(id)
    except ValueError:
        return jsonify({"error": "invalid id"}), 400
    ex = exploits.get(eid)
    if not ex:
        return jsonify({"error": "not found"}), 404

    body = request.get_json(silent=True) or {}
    targets = _parse_targets(body.get("targets"))
    if targets is None:
        return jsonify({"error": "targets must be a non-empty list"}), 400
    timeout = _parse_timeout(body)
    try:
        port_override = _parse_port_override(body)
        payload_override = _parse_payload_override(body)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    payload = payload_override if payload_override is not None else ex.payload
    port = port_override if port_override is not None else ex.port
    result = attack.replay_payload(
        payload, port, targets, timeout=timeout, result_id=str(ex.id),
        rewrite_host=(payload_override is None),
    )
    audit.log(
        auth.current_user() or "?", "exploits.replay",
        target=str(ex.id), details={
            "target_count": len(targets), "timeout": timeout,
            "port_overridden": port_override is not None,
            "payload_overridden": payload_override is not None,
        },
    )
    return return_json_response(result)


@application.route("/exploits/<id>/exploit-script")
def exploit_script(id):
    try:
        eid = uuid.UUID(id)
    except ValueError:
        return return_text_response("# error: invalid id"), 400
    ex = exploits.get(eid)
    if not ex:
        return return_text_response("# error: not found"), 404

    teams = app_config.get("teams") or []
    try:
        timeout = float(request.args.get("timeout", attack.DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = attack.DEFAULT_TIMEOUT
    script = attack.generate_script_from_payload(
        ex.payload, ex.port, str(ex.id), teams, timeout=timeout,
    )
    return Response(
        script,
        mimetype="text/x-python",
        headers={
            "Content-Disposition":
                f'attachment; filename="w4rya_exploit_{_exploit_script_filename(ex.name)}.py"'
        },
    )


# --- /audit (admin-only log) -----------------------------------------------

def _audit_query_args():
    """Parse common audit filter args. Used by both JSON + CSV endpoints."""
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    actor = (request.args.get("actor") or "").strip() or None
    action_prefix = (request.args.get("action") or "").strip() or None
    after_raw = (request.args.get("from") or "").strip()
    after_ts = None
    if after_raw:
        try:
            after_ts = dateutil.parser.parse(after_raw)
            if after_ts.tzinfo is None:
                after_ts = after_ts.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            after_ts = None
    return {
        "limit": max(10, min(10_000, limit)),
        "actor": actor,
        "action_prefix": action_prefix,
        "after_ts": after_ts,
    }


@application.route("/audit")
@auth.requires_role("admin")
def audit_recent():
    args = _audit_query_args()
    rows = audit.recent(**args)
    return return_json_response({"count": len(rows), "events": rows})


@application.route("/audit/actors")
@auth.requires_role("admin")
def audit_distinct_actors():
    return return_json_response(audit.distinct_actors())


@application.route("/audit/export.csv")
@auth.requires_role("admin")
def audit_export_csv():
    args = _audit_query_args()
    # Bigger cap for exports
    args["limit"] = min(50_000, max(args["limit"], 1000))
    rows = audit.recent(**args)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["when", "actor", "action", "target", "details"])
    for r in rows:
        w.writerow([
            r["when"],
            r["actor"],
            r["action"],
            r["target"] or "",
            json.dumps(r["details"], default=str) if r["details"] else "",
        ])
    fname = "w4rya_audit_" + datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


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
        return suricata_ctl.reload_rules(blocking=False)
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


@application.route("/flow/<id>/decode")
def getFlowDecoded(id):
    """Auto-decode every raw item in this flow (base64/hex/url/gzip/deflate,
    recursively) — saves the monitoring team a manual round-trip through
    CyberChef for the common case. Items with nothing decodable are omitted
    rather than returned with an empty layer list."""
    try:
        id = uuid.UUID(id)
    except ValueError:
        return jsonify({"error": "invalid id"}), 400
    with db.connection() as c:
        flow = c.flow_detail(id)
    if not flow:
        return jsonify({"error": "flow not found"}), 404
    out = []
    for idx, item in enumerate(flow.items):
        if item.kind != "raw":
            continue
        found = decode.decode_item(item.data)
        if not found["whole"] and not found["embedded"]:
            continue
        out.append({
            "item_index": idx,
            "direction": item.direction,
            "raw_size": len(item.data),
            **found,
        })
    return return_json_response({"flow_id": str(flow.id), "items": out})


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
    raw = request.args.get("file")
    if raw is None:
        return return_text_response("error: no 'file' given"), 400

    # D1: tightened path-traversal guard. We resolve BOTH sides (so a
    # trailing slash or symlink in the env-derived allowlist doesn't widen
    # the check), then use is_relative_to (Python 3.9+) so '..' in the
    # user path can't escape. lexists+is_symlink rejects symlink trickery.
    try:
        req = Path(raw)
        if req.is_absolute():
            target = req.resolve(strict=False)
        else:
            target = (traffic_dir / req).resolve(strict=False)
    except (OSError, ValueError):
        return return_text_response("error: invalid path"), 400

    allow_roots = []
    for root in (traffic_dir, dump_pcaps_dir):
        try:
            allow_roots.append(Path(root).resolve(strict=False))
        except (OSError, ValueError):
            continue
    if not any(target == r or target.is_relative_to(r) for r in allow_roots):
        return return_text_response("error: path outside allowed roots"), 403

    if target.is_symlink():
        return return_text_response("error: symlinks not allowed"), 403
    if not target.exists():
        return return_text_response("error: file not found"), 404

    return send_file(str(target), as_attachment=True)

def create_app():
    # D1: surface module-level warnings/errors via gunicorn's stderr.
    # Without this, audit.log _log.warning calls and other module loggers
    # vanish silently (root logger defaults to WARNING but with no handler).
    log_level_name = os.environ.get("W4RYA_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level_name, logging.INFO),
        format="[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
    )
    db.open()
    app_config.set_pool(db)
    app_config.init_schema()
    notes.set_pool(db)
    notes.init_schema()
    audit.set_pool(db)
    audit.init_schema()
    exploits.set_pool(db)
    exploits.init_schema()
    return application

if __name__ == "__main__":
    try:
        db.open()
        application.run(host="0.0.0.0", threaded=True)
    finally:
        db.close()
