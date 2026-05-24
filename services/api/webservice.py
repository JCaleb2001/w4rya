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
        return jsonify({"error": "invalid credentials"}), 401
    session.clear()
    session["user"] = username
    session.permanent = True
    return jsonify({"user": username})


@application.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@application.route("/me")
def me():
    return jsonify({"user": auth.current_user()})


@application.route("/tick_info")
def getTickInfo():
    data = {
        "startDate": start_date,
        "tickLength": tick_length,
        "flagLifetime": flag_lifetime,
    }
    return return_json_response(data)


@application.route("/query", methods=["POST"])
def query():
    query = request.get_json()

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
    res = get(
        f"{visualizer_url}/api/under-attack",
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
def setStar():
    query = request.get_json()
    flow_id = uuid.UUID(query.get("id"))
    apply = bool(query.get("star"))
    with db.connection() as c:
        c.flow_tag(flow_id, "starred", apply)
    return "ok!"


@application.route("/services")
def getServices():
    return return_json_response(services)


@application.route("/flag_regex")
def getFlagRegex():
    return return_json_response(flag_regex)


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
    return application

if __name__ == "__main__":
    try:
        db.open()
        application.run(host="0.0.0.0", threaded=True)
    finally:
        db.close()
