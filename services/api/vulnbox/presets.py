"""Game presets: named bundles of /config values for one A/D game.

The code is game-agnostic; whatever belongs to a single competition — round
length, flag format, game start, which ports are game services — lives here
as data. Supporting another game means adding one `Preset` entry; nothing
else changes. Every entry is validated against the same write-time checks as
PUT /config (see tests/vulnbox/test_presets.py), so a bad value fails the test
suite rather than the operator mid-game.

Applied from the /vulnbox page (admin). The assembler reads some of these
settings from `.env` at boot rather than from /config; `ASSEMBLER_ENV` maps
them so the UI can show the matching `.env` lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional


@dataclass(frozen=True)
class Preset:
    id: str            # stable, url-safe: used in POST /vulnbox/presets/<id>
    name: str          # shown in the UI
    values: Mapping[str, object] = field(default_factory=dict)


# /config key → the .env variable the Go assembler reads at boot.
ASSEMBLER_ENV: Mapping[str, str] = {
    "flag_regex": "FLAG_REGEX",
    "tick_length": "TICK_LENGTH",
    "start_date": "TICK_START",
    "flag_lifetime": "FLAG_LIFETIME",
}


PRESETS: tuple[Preset, ...] = (
    Preset(
        id="ecsc-2026",
        name="ECSC 2026",
        values={
            # 60 s rounds.
            "tick_length": 60000,
            # Valid in the round it was placed + 4 more. w4rya's flag_lifetime
            # counts the current round too, hence 5.
            "flag_lifetime": 5,
            # The official ^...$ pattern, unanchored: w4rya searches for flags
            # inside traffic, where an anchored pattern never matches.
            "flag_regex": r"ECSC\{[A-Za-z0-9_-]{32}\}",
            # Scored game start (11:00 CEST).
            "start_date": "2026-10-15T09:00:00Z",
            # The game firewall only lets other teams reach this range.
            "vulnbox_service_ports": "9000-9999",
        },
    ),
)


def get(preset_id: str) -> Optional[Preset]:
    return next((p for p in PRESETS if p.id == preset_id), None)
