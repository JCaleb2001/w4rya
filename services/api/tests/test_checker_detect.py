"""Tests for checker_detect.py — the deterministic checker-candidate scorer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _regular_times(n: int, interval_s: float, start=None) -> list[datetime]:
    start = start or datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
    return [start + timedelta(seconds=i * interval_s) for i in range(n)]


def _irregular_times() -> list[datetime]:
    start = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
    offsets = [0, 3, 47, 51, 52, 130, 900, 905, 1400]  # bursty, human-like
    return [start + timedelta(seconds=o) for o in offsets]


def test_perfectly_regular_checker_scores_high():
    import checker_detect
    times = _regular_times(20, interval_s=180.0)  # exactly once per 3-min tick
    out = checker_detect.score_ip(
        times=times,
        distinct_dst_ports={2112, 5151, 8000, 8008, 5885},
        flow_count=20,
        alert_flow_count=0,
        total_known_ports=5,
    )
    assert out["confidence"] > 0.9
    assert out["evidence"]["interval_regularity"] > 0.95
    assert out["evidence"]["service_coverage"] == 1.0
    assert out["evidence"]["clean_signature_rate"] == 1.0


def test_bursty_human_like_traffic_scores_low():
    import checker_detect
    out = checker_detect.score_ip(
        times=_irregular_times(),
        distinct_dst_ports={8008},
        flow_count=9,
        alert_flow_count=3,
        total_known_ports=5,
    )
    assert out["confidence"] < 0.4


def test_attacker_using_same_tooling_as_checker_but_triggering_alerts_scores_lower():
    """Same regular cadence as the checker (e.g. an attacker replaying its
    schedule) but with signature hits should score meaningfully lower —
    regularity alone isn't a free pass."""
    import checker_detect
    times = _regular_times(20, interval_s=180.0)
    regular_clean = checker_detect.score_ip(
        times=times, distinct_dst_ports={2112, 5151, 8000, 8008, 5885},
        flow_count=20, alert_flow_count=0, total_known_ports=5,
    )
    regular_dirty = checker_detect.score_ip(
        times=times, distinct_dst_ports={2112, 5151, 8000, 8008, 5885},
        flow_count=20, alert_flow_count=20, total_known_ports=5,
    )
    assert regular_dirty["confidence"] < regular_clean["confidence"]


def test_too_few_samples_caps_confidence_even_with_perfect_supporting_signals():
    import checker_detect
    out = checker_detect.score_ip(
        times=[datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)],  # 1 sample
        distinct_dst_ports={2112, 5151, 8000, 8008, 5885},
        flow_count=1,
        alert_flow_count=0,
        total_known_ports=5,
    )
    assert out["evidence"]["interval_regularity"] is None
    assert out["confidence"] <= 0.4


def test_zero_known_ports_does_not_divide_by_zero():
    import checker_detect
    out = checker_detect.score_ip(
        times=_regular_times(5, 180.0),
        distinct_dst_ports=set(),
        flow_count=5,
        alert_flow_count=0,
        total_known_ports=0,
    )
    assert out["evidence"]["service_coverage"] == 0.0


def test_zero_flow_count_does_not_divide_by_zero():
    import checker_detect
    out = checker_detect.score_ip(
        times=[], distinct_dst_ports=set(), flow_count=0,
        alert_flow_count=0, total_known_ports=5,
    )
    assert out["evidence"]["clean_signature_rate"] == 0.0
    assert out["confidence"] >= 0.0


def test_partial_service_coverage_scores_between_full_and_none():
    import checker_detect
    times = _regular_times(20, 180.0)
    full = checker_detect.score_ip(
        times=times, distinct_dst_ports={1, 2, 3, 4, 5},
        flow_count=20, alert_flow_count=0, total_known_ports=5,
    )
    partial = checker_detect.score_ip(
        times=times, distinct_dst_ports={1},
        flow_count=20, alert_flow_count=0, total_known_ports=5,
    )
    assert partial["confidence"] < full["confidence"]
