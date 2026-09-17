"""Deterministic "is this IP probably the gameserver checker?" scorer.

NO AI: plain statistics over already-recorded flow metadata (timestamps,
destination ports, whether Suricata matched a signature). A User-Agent
string is NOT used as a signal here — a real attacker's exploit script is
just as likely to run on `python-requests` as the checker is, so a UA match
would misclassify real attacks as benign. What a checker can't fake without
literally being rewritten is its *rhythm*: it runs on the same cron/tick
schedule every round, hits every configured service, and never trips an
exploit signature because it's exercising the service the way it was meant
to be used.

This produces a ranked *suggestion* for a human to confirm — it never
excludes an IP on its own. See webservice.py's /checker/candidates and
/config/checker-ips.
"""

from __future__ import annotations

import statistics
from datetime import datetime


def _coefficient_of_variation(times: list[datetime]) -> float | None:
    """Lower = more regular (checker-like); returns None with too few
    samples to say anything. Interval-based, not absolute-time-based, so it
    doesn't matter when in the match this IP was active."""
    if len(times) < 3:
        return None
    ordered = sorted(times)
    gaps = [
        (b - a).total_seconds()
        for a, b in zip(ordered, ordered[1:])
    ]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < 2:
        return None
    mean = statistics.mean(gaps)
    if mean <= 0:
        return None
    return statistics.pstdev(gaps) / mean


def score_ip(
    *,
    times: list[datetime],
    distinct_dst_ports: set[int],
    flow_count: int,
    alert_flow_count: int,
    total_known_ports: int,
) -> dict:
    """Score one src_ip's behavior over some analysis window.

    Weights: interval regularity carries the most weight (0.5) because it's
    the hardest signal for either side to fake — an attacker replaying a
    checker's exact cadence would just look like a second checker, which is
    a fine thing to also flag for a human to look at. Service coverage
    (0.3) and a clean signature record (0.2) are supporting evidence.
    """
    cv = _coefficient_of_variation(times)
    regularity = None if cv is None else max(0.0, 1.0 - min(cv, 1.0))
    coverage = (
        len(distinct_dst_ports) / total_known_ports if total_known_ports else 0.0
    )
    clean_rate = 1.0 - (alert_flow_count / flow_count) if flow_count else 0.0

    confidence = (
        0.5 * (regularity or 0.0)
        + 0.3 * coverage
        + 0.2 * clean_rate
    )
    # Without enough samples to judge regularity, the strongest signal is
    # simply missing — cap confidence rather than let the other two carry
    # a "confident" verdict on their own (coverage+clean alone is also true
    # of an idle, harmless attacker who just hasn't done much yet).
    if regularity is None:
        confidence = min(confidence, 0.4)

    return {
        "confidence": round(confidence, 3),
        "evidence": {
            "interval_regularity": None if regularity is None else round(regularity, 3),
            "coefficient_of_variation": None if cv is None else round(cv, 3),
            "service_coverage": round(coverage, 3),
            "services_touched": len(distinct_dst_ports),
            "services_total": total_known_ports,
            "clean_signature_rate": round(clean_rate, 3),
            "flow_count": flow_count,
            "alert_flow_count": alert_flow_count,
        },
    }
