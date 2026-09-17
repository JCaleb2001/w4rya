#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import json
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Iterator, cast

import dateutil.parser
import psycopg
import psycopg_pool
from psycopg import sql
from psycopg.rows import class_row, dict_row

import app_config
import checker_detect
import configurations
import technique_map
from json_util import JsonFactory


@dataclass(slots=True, kw_only=True)
class FlowQuery:
    regex_insensitive: re.Pattern | None = None
    ip_src: IPv4Network | IPv6Network | None = None
    ip_dst: IPv4Network | IPv6Network | None = None
    port_src: int | None = None
    port_dst: int | None = None
    # Multi-service filter: list of (ip, port) pairs OR-ed together. Lets the
    # UI multi-select chips translate to a single SQL query.
    services: list[tuple[IPv4Network | IPv6Network, int]] = field(default_factory=list)
    # Sources to drop: the checker and our own tooling. Excluded rather
    # than filtered in the UI so the row limit is spent on real traffic.
    ip_src_exclude: list[IPv4Network | IPv6Network] = field(default_factory=list)
    time_from: datetime | None = None
    time_to: datetime | None = None
    tags_include: list[str] = field(default_factory=list)
    tags_exclude: list[str] = field(default_factory=list)
    tag_intersection_and: bool = False
    # Substring match (case-insensitive) against the source pcap's filename.
    # Sidesteps the tick/time filter entirely — useful for a pcap whose own
    # capture timestamp falls way outside the game's tick-0 anchor (e.g. a
    # historical/test pcap loaded for detection testing), where no time
    # window is going to surface it without knowing that offset in advance.
    pcap_name: str | None = None
    limit: int = 1000


@dataclass(slots=True, kw_only=True)
class Flow:
    id: uuid.UUID
    time: datetime
    port_src: int
    port_dst: int
    ip_src: IPv4Address | IPv6Address
    ip_dst: IPv4Address | IPv6Address
    duration: timedelta
    pcap_id: uuid.UUID
    pcap_name: str
    link_parent_id: uuid.UUID
    link_child_id: uuid.UUID
    fingerprints: list[int]
    packets_count: int
    packets_size: int
    flags_in: int
    flags_out: int
    signatures: list[Signature]
    tags: list[str]
    flags: list[str]
    flagids: list[str]
    rank: int = 0


@dataclass(slots=True, kw_only=True)
class Signature:
    id: int
    message: str
    action: str


@dataclass(slots=True, kw_only=True)
class FlowItem(JsonFactory):
    id: uuid.UUID
    flow_id: uuid.UUID
    kind: str
    time: datetime
    direction: str
    data: bytes

    def to_json(self) -> Any:
        result = JsonFactory.to_json(self)
        result["data"] = base64.b64encode(result["data"]).decode("ascii")
        return result


@dataclass(slots=True, kw_only=True)
class FlowDetail(Flow):
    items: list[FlowItem] = field(default_factory=list)

    def kind_items(self, kind: str = "raw") -> list[FlowItem]:
        return [i for i in self.items if i.kind == kind]

    def item_data(self, kind: str = "raw") -> list[bytes]:
        return [i.data for i in self.kind_items(kind)]

    def collect_data(self, kind: str = "raw") -> bytes:
        return b"".join(self.item_data(kind))


@dataclass(slots=True, kw_only=True)
class StatsQuery:
    service: str | None = None
    tick_from: int | None = None
    tick_to: int | None = None


@dataclass(slots=True)
class Stats:
    tick: int
    flow_count: int = 0
    tag_flag_in: int = 0
    tag_flag_out: int = 0
    tag_blocked: int = 0
    tag_suricata: int = 0
    tag_enemy: int = 0
    flag_in: int = 0
    flag_out: int = 0


class Pool(psycopg_pool.ConnectionPool):
    def __init__(self, connection_string: str, *, open: bool = False, **kwargs) -> None:
        super().__init__(
            connection_string,
            open=open,
            connection_class=Connection,
            **kwargs,
        )

    @contextmanager
    def connection(self, timeout: float | None = None) -> Iterator[Connection]:
        with super().connection(timeout) as connection:
            yield cast(Connection, connection)


class Connection(psycopg.Connection):
    def flow_query(self, query: FlowQuery) -> list[Flow]:
        pre_select = sql.SQL(
            "WITH f AS (SELECT *, fid_rank_desc(id) AS rank FROM flow ORDER BY id DESC)"
        )
        conditions = [sql.SQL("true")]
        pre_conditions = [sql.SQL("true")]
        parameters = {}

        if query.ip_src:
            parameters["ip_src"] = query.ip_src
            conditions.append(sql.SQL("f.ip_src <<= %(ip_src)s"))
        if query.ip_dst:
            parameters["ip_dst"] = query.ip_dst
            conditions.append(sql.SQL("f.ip_dst <<= %(ip_dst)s"))

        if query.port_src:
            parameters["port_src"] = query.port_src
            conditions.append(sql.SQL("f.port_src = %(port_src)s"))
        if query.port_dst:
            parameters["port_dst"] = query.port_dst
            conditions.append(sql.SQL("f.port_dst = %(port_dst)s"))

        if query.services:
            pair_sqls = []
            for i, (svc_ip, svc_port) in enumerate(query.services):
                ip_key = f"svc_ip_{i}"
                port_key = f"svc_port_{i}"
                parameters[ip_key] = svc_ip
                parameters[port_key] = svc_port
                pair_sqls.append(
                    sql.SQL("(f.ip_dst <<= %({ip})s AND f.port_dst = %({port})s)").format(
                        ip=sql.SQL(ip_key), port=sql.SQL(port_key)
                    )
                )
            conditions.append(sql.SQL("(") + sql.SQL(" OR ").join(pair_sqls) + sql.SQL(")"))

        if query.ip_src_exclude:
            excl_sqls = []
            for i, net in enumerate(query.ip_src_exclude):
                key = f"ip_src_excl_{i}"
                parameters[key] = net
                excl_sqls.append(sql.SQL("f.ip_src <<= %({k})s").format(k=sql.SQL(key)))
            conditions.append(
                sql.SQL("NOT (") + sql.SQL(" OR ").join(excl_sqls) + sql.SQL(")")
            )

        if query.time_from:
            parameters["time_from"] = query.time_from
            conditions.append(sql.SQL("f.id > fid_pack_low(%(time_from)s)"))
            pre_conditions.append(sql.SQL("flow_id > fid_pack_low(%(time_from)s)"))
        if query.time_to:
            parameters["time_to"] = query.time_to
            conditions.append(sql.SQL("f.id < fid_pack_high(%(time_to)s)"))
            pre_conditions.append(sql.SQL("flow_id < fid_pack_high(%(time_to)s)"))

        if query.pcap_name:
            parameters["pcap_name"] = f"%{query.pcap_name}%"
            conditions.append(sql.SQL("p.name ILIKE %(pcap_name)s"))

        if query.tags_include:
            parameters["tags_include"] = query.tags_include
            if query.tag_intersection_and:
                conditions.append(sql.SQL("f.tags ?& %(tags_include)s"))
            else:
                conditions.append(sql.SQL("f.tags ?| %(tags_include)s"))
        if query.tags_exclude:
            parameters["tags_exclude"] = query.tags_exclude
            conditions.append(sql.SQL("NOT f.tags ?| %(tags_exclude)s"))

        if query.regex_insensitive:
            parameters["regex_insensitive"] = query.regex_insensitive.pattern
            text = """
                WITH fi AS (
                    SELECT flow_id, fid_rank_desc(flow_id) AS rank
                    FROM flow_index
                    WHERE text ~* %(regex_insensitive)s
                        AND {pre_conditions}
                    ORDER BY rank
                ), fd AS (
                    SELECT DISTINCT flow_id, rank
                    FROM fi
                ), f AS (
                    SELECT fl.*, fd.rank
                    FROM fd
                    LEFT JOIN flow AS fl
                        ON fl.id = fd.flow_id
                )
            """
            pre_select = sql.SQL(text).format(
                pre_conditions=sql.SQL(" AND ").join(pre_conditions)
            )

        text_query = """
            /*+
                IndexScan(flow_index)
                Set(enable_material false)
            */
            {pre_select}
            SELECT f.*, p.name AS pcap_name
            FROM f
            LEFT JOIN pcap AS p
                ON p.id = f.pcap_id
            WHERE {conditions}
            LIMIT {limit}
        """

        sql_query = sql.SQL(text_query).format(
            conditions=sql.SQL(" AND ").join(conditions),
            pre_select=pre_select,
            limit=query.limit,
        )

        with self.cursor(row_factory=class_row(Flow)) as cursor:
            flows = cursor.execute(sql_query, parameters).fetchall()

        # Filter out non-existing tags
        tags = self.tag_list()
        for flow in flows:
            flow.tags = list(filter(lambda t: t in flow.tags, tags))

        return list(sorted(flows, key=lambda f: f.rank))

    def flow_detail(self, id: uuid.UUID) -> FlowDetail | None:
        sql_query = """
            SELECT f.*, p.name AS pcap_name
            FROM flow AS f
            INNER JOIN pcap AS p
                ON p.id = f.pcap_id
            WHERE f.id = %(id)s
            ORDER BY id DESC
            LIMIT 2000
        """
        with self.cursor(row_factory=class_row(FlowDetail)) as cursor:
            flow = cursor.execute(sql_query, {"id": id}).fetchone()

        if flow is None:
            return None

        flow.items = self.flow_item_query(flow)

        # Filter out non-existing tags and sort the rest
        flow.tags = list(filter(lambda t: t in flow.tags, self.tag_list()))

        return flow

    def flow_item_query(self, flow: Flow) -> list[FlowItem]:
        sql_query = """
            SELECT fi.*
            FROM flow_item AS fi
            WHERE fi.flow_id = %(flow_id)s
                AND fi.id > fid_pack_low(%(time_start)s)
                AND fi.id < fid_pack_high(%(time_end)s)
            ORDER BY fi.id
        """

        parameters = {
            "flow_id": flow.id,
            "time_start": flow.time,
            "time_end": flow.time + flow.duration,
        }

        with self.cursor(row_factory=class_row(FlowItem)) as cursor:
            return cursor.execute(sql_query, parameters).fetchall()

    def flow_tag(self, flow_id: uuid.UUID, tag: str, apply: bool) -> None:
        if apply:
            sql_query = """
                UPDATE flow
                SET tags = jsonb_unique(tags || jsonb_build_array(%(tag)s::text))
                WHERE id = %(flow_id)s
            """
        else:
            sql_query = """
                UPDATE flow
                SET tags = tags - %(tag)s::text
                WHERE id = %(flow_id)s
            """

        self.execute(sql_query, {"flow_id": flow_id, "tag": tag})

    def stats_query(self, query: StatsQuery) -> dict[int, Stats]:
        now = datetime.now(tz=timezone.utc)
        tick_first = dateutil.parser.parse(app_config.get("start_date"))
        tick_length = timedelta(milliseconds=int(app_config.get("tick_length")))
        tick_current = ((now - tick_first) // tick_length) + 1
        tick_start = query.tick_from if query.tick_from else 0
        tick_end = query.tick_to if query.tick_to else tick_current
        time_start = tick_first + (tick_start * tick_length)
        time_end = tick_first + (tick_end * tick_length)

        stats: dict[int, Stats] = {i: Stats(i) for i in range(tick_start, tick_end)}

        parameters = {
            "tick_length": tick_length,
            "tick_first": tick_first,
            "time_start": time_start,
            "time_end": time_end,
        }

        sql_query = """
            SELECT tick_number_bucket(%(tick_first)s, %(tick_length)s, time) AS tick,
                count(id) AS count, sum(flags_in) AS flags_in, sum(flags_out) AS flags_out
            FROM flow AS f
            WHERE f.id > fid_pack_low(%(time_start)s)
                AND f.id < fid_pack_high(%(time_end)s)
            GROUP BY tick
        """
        with self.cursor(row_factory=dict_row) as cursor:
            for row in cursor.execute(sql_query, parameters):
                stats[row["tick"]].flow_count = row["count"]
                stats[row["tick"]].flag_in = row["flags_in"]
                stats[row["tick"]].flag_out = row["flags_out"]

        # TODO: Maybe count all tags? The query already selects the numbers
        sql_query = """
            SELECT tick_time_bucket(%(tick_first)s, %(tick_length)s, time) AS tick_start,
                tick_number_bucket(%(tick_first)s, %(tick_length)s, time) AS tick,
                t.name AS tag, count(f.id) AS count
            FROM flow AS f
            JOIN tag AS t
                ON f.tags ? t.name
            WHERE f.id > fid_pack_low(%(time_start)s)
                AND f.id < fid_pack_high(%(time_end)s)
            GROUP BY tick_start, tick, t.name
            ORDER BY tick ASC
        """
        with self.cursor(row_factory=dict_row) as cursor:
            for row in cursor.execute(sql_query, parameters):
                if row["tag"] == "flag-in":
                    stats[row["tick"]].tag_flag_in += row["count"]
                elif row["tag"] == "flag-out":
                    stats[row["tick"]].tag_flag_out += row["count"]
                elif row["tag"] == "blocked":
                    stats[row["tick"]].tag_blocked += row["count"]
                elif row["tag"] == "suricata":
                    stats[row["tick"]].tag_suricata += row["count"]
                elif row["tag"] == "enemy":
                    stats[row["tick"]].tag_enemy += row["count"]

        return stats

    def tag_list(self) -> list[str]:
        with self.cursor(row_factory=dict_row) as cursor:
            tags = cursor.execute("SELECT name FROM tag ORDER BY sort ASC").fetchall()
            return [t["name"] for t in tags]

    def attack_timeline(
        self,
        time_from: datetime,
        time_to: datetime,
        services: list[dict],
        service_filter: str | None = None,
        limit: int = 200,
        exclude_ips: set[str] | None = None,
    ) -> list[dict]:
        """Chronological list of attack-flavored events in the time window.

        An 'event' is any flow that either matched a Suricata signature OR
        leaked a flag (tag = flag-out). For each event we resolve the dst
        (ip, port) to the configured service name.

        `exclude_ips`: confirmed checker/gameserver IPs (app_config's
        `checker_ips`, set via /checker/candidates) — excluded in SQL,
        before LIMIT, so a busy checker can't push real attacker events
        out of the already-limited result set.
        """
        sql_query = """
            SELECT id, time,
                   ip_src::text AS ip_src,
                   ip_dst::text AS ip_dst,
                   port_src, port_dst,
                   flags_out, signatures, tags
            FROM flow
            WHERE (jsonb_array_length(signatures) > 0 OR tags ? 'flag-out')
              AND id > fid_pack_low(%(t0)s)
              AND id < fid_pack_high(%(t1)s)
              AND NOT (host(ip_src) = ANY(%(exclude_ips)s::text[]))
            ORDER BY time DESC
            LIMIT %(limit)s
        """
        with self.cursor(row_factory=dict_row) as cursor:
            rows = cursor.execute(
                sql_query,
                {
                    "t0": time_from, "t1": time_to, "limit": limit,
                    "exclude_ips": sorted(exclude_ips) if exclude_ips else [],
                },
            ).fetchall()

        svc_by_key = {
            (str(s.get("ip", "")), int(s.get("port", -1) or 0)): s.get("name", "?")
            for s in services
        }
        out: list[dict] = []
        for r in rows:
            ip_dst = str(r["ip_dst"]).split("/", 1)[0]
            ip_src = str(r["ip_src"]).split("/", 1)[0]
            svc_name = svc_by_key.get((ip_dst, int(r["port_dst"])), "unknown")
            if service_filter and svc_name != service_filter:
                continue
            sigs = r.get("signatures") or []
            tags = r.get("tags") or []
            has_flag = "flag-out" in tags
            has_alert = bool(sigs)
            if has_alert and has_flag:
                ev_type = "both"
            elif has_alert:
                ev_type = "alert"
            else:
                ev_type = "flag_out"
            rules = [
                {
                    "id": s.get("id"),
                    "message": s.get("message"),
                    "action": s.get("action"),
                    **technique_map.classify(s.get("message")),
                }
                for s in sigs
            ]
            # Highest-severity rule wins the event's headline tactic — the
            # kill-chain view sorts/colors by this rather than by rule order,
            # which is just "whichever rule Suricata evaluated first".
            tactic, severity = technique_map.summarize(
                rules, has_flag_only=has_flag and not has_alert
            )
            out.append({
                "flow_id": str(r["id"]),
                "time": r["time"].isoformat(),
                "src_ip": ip_src,
                "src_port": int(r["port_src"]),
                "dst_ip": ip_dst,
                "dst_port": int(r["port_dst"]),
                "service": svc_name,
                "type": ev_type,
                "tactic": tactic,
                "severity": severity,
                "rules": rules,
                "flag_out_count": int(r["flags_out"] or 0) if has_flag else 0,
            })
        return out

    def incident_stats(self, sid: int, src_ip: str) -> dict:
        """First/last-seen + occurrence count for one (rule sid, src_ip) pair,
        across the whole retained window — feeds the incident-packet builder
        (webservice.attack_incident) so an alert reads as "this technique,
        from this source, N times since <date>" instead of a single flow in
        isolation.
        """
        sql_query = """
            SELECT MIN(time) AS first_seen, MAX(time) AS last_seen, COUNT(*) AS occurrence_count
            FROM flow
            WHERE ip_src = %(src_ip)s::inet
              AND signatures @> %(sig)s::jsonb
        """
        with self.cursor(row_factory=dict_row) as cursor:
            row = cursor.execute(
                sql_query,
                {"src_ip": src_ip, "sig": json.dumps([{"id": sid}])},
            ).fetchone()
        if not row or not row["occurrence_count"]:
            return {"first_seen": None, "last_seen": None, "occurrence_count": 0}
        return {
            "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
            "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            "occurrence_count": int(row["occurrence_count"]),
        }

    def checker_candidates(
        self,
        time_from: datetime,
        time_to: datetime,
        total_known_ports: int,
        exclude_ips: set[str] | None = None,
        limit: int = 10,
    ) -> list[dict]:
        """Rank src_ips in the window by how checker-like their traffic
        looks (see checker_detect.score_ip) — gathers per-ip timing/coverage/
        signature stats in one grouped query and hands them to the scorer.
        """
        sql_query = """
            SELECT ip_src::text AS ip_src,
                   array_agg(time) AS times,
                   array_agg(DISTINCT port_dst) AS ports,
                   count(*) AS flow_count,
                   count(*) FILTER (WHERE jsonb_array_length(signatures) > 0) AS alert_count
            FROM flow
            WHERE id > fid_pack_low(%(t0)s) AND id < fid_pack_high(%(t1)s)
            GROUP BY ip_src
        """
        with self.cursor(row_factory=dict_row) as cursor:
            rows = cursor.execute(
                sql_query, {"t0": time_from, "t1": time_to}
            ).fetchall()

        exclude_ips = exclude_ips or set()
        out: list[dict] = []
        for r in rows:
            ip_src = str(r["ip_src"]).split("/", 1)[0]
            if ip_src in exclude_ips:
                continue
            scored = checker_detect.score_ip(
                times=list(r["times"] or []),
                distinct_dst_ports=set(r["ports"] or []),
                flow_count=int(r["flow_count"] or 0),
                alert_flow_count=int(r["alert_count"] or 0),
                total_known_ports=total_known_ports,
            )
            out.append({"ip": ip_src, **scored})
        out.sort(key=lambda x: x["confidence"], reverse=True)
        return out[:limit]

    def per_service_stats(self, time_start: datetime, services: list[dict]) -> list[dict]:
        """Aggregate flow / attack / flag counts for each configured service.

        We do one grouped scan over the flow table for the time window, then
        align the (ip, port) result rows against the services config. Services
        with zero matching flows still come back (with zero counters) so the
        UI can show every chip consistently.
        """
        sql_query = """
            SELECT ip_dst::text AS ip_dst,
                   port_dst,
                   count(*)                                              AS flows,
                   sum(CASE WHEN jsonb_array_length(signatures) > 0
                            THEN 1 ELSE 0 END)                           AS attacks,
                   sum(flags_in)                                         AS flag_in,
                   sum(flags_out)                                        AS flag_out
            FROM flow
            WHERE id > fid_pack_low(%(time_start)s)
            GROUP BY ip_dst, port_dst
        """
        with self.cursor(row_factory=dict_row) as cursor:
            rows = cursor.execute(sql_query, {"time_start": time_start}).fetchall()
        # Index by (ip_string_no_prefix, port). ip_dst comes back as CIDR
        # ('10.10.3.1/32'), strip the suffix to compare with the plain ips in
        # the services config.
        by_key: dict[tuple[str, int], dict] = {}
        for r in rows:
            ip_clean = str(r["ip_dst"]).split("/", 1)[0]
            by_key[(ip_clean, int(r["port_dst"]))] = r

        out: list[dict] = []
        for s in services:
            row = by_key.get((str(s.get("ip", "")), int(s.get("port", -1) or 0)))
            out.append({
                "name": s.get("name"),
                "ip": s.get("ip"),
                "port": s.get("port"),
                "flows": int(row["flows"]) if row else 0,
                "attacks": int(row["attacks"]) if row else 0,
                "flag_in": int(row["flag_in"] or 0) if row else 0,
                "flag_out": int(row["flag_out"] or 0) if row else 0,
            })
        return out

    def pipeline_health(self, tick_start: datetime, hour_start: datetime,
                        horizon: datetime) -> dict:
        """Freshness of the ingest pipeline: newest flow, and recent volume.

        Every predicate goes through fid_pack_low(...) on the primary key
        rather than the generated `time` column, which is what the rest of the
        query paths do -- `time` has no index of its own, so a bare max(time)
        would scan the whole table. `horizon` bounds the max(): if nothing has
        been ingested since then the answer is NULL, which the caller reads as
        "no recent traffic" rather than paying for a full scan to find some
        flow from three games ago.
        """
        sql_query = """
            SELECT max(time)                                         AS last_flow_time,
                   count(*) FILTER (WHERE id > fid_pack_low(%(tick_start)s)) AS flows_last_tick,
                   count(*) FILTER (WHERE id > fid_pack_low(%(hour_start)s)) AS flows_last_hour
            FROM flow
            WHERE id > fid_pack_low(%(horizon)s)
        """
        with self.cursor(row_factory=dict_row) as cursor:
            row = cursor.execute(sql_query, {
                "tick_start": tick_start,
                "hour_start": hour_start,
                "horizon": horizon,
            }).fetchone()
        return {
            "last_flow_time": row["last_flow_time"] if row else None,
            "flows_last_tick": int(row["flows_last_tick"] or 0) if row else 0,
            "flows_last_hour": int(row["flows_last_hour"] or 0) if row else 0,
        }

    def ingested_pcap_names(self) -> list[str]:
        """Basenames of every pcap the assembler has recorded.

        The assembler stores the path it opened ("/traffic/foo.pcap"), so the
        caller compares basenames against what is on disk.
        """
        with self.cursor() as cursor:
            rows = cursor.execute("SELECT name FROM pcap").fetchall()
        return [str(r[0]).rsplit("/", 1)[-1] for r in rows]
