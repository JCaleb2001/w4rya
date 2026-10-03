"""Game presets are data: every entry must pass the same write-time checks as
PUT /config, so adding a game can't ship a value that breaks /config."""

import re

import pytest

import app_config
from vulnbox import presets


@pytest.mark.parametrize("preset", presets.PRESETS, ids=lambda p: p.id)
def test_every_preset_value_is_a_valid_config_value(preset):
    assert preset.values, "a preset must set something"
    for key, raw in preset.values.items():
        assert key in app_config.SCALAR_KEYS, f"{preset.id}: unknown /config key {key!r}"
        app_config.coerce_scalar(key, raw)  # raises on an invalid value


def test_preset_ids_are_unique_and_url_safe():
    ids = [p.id for p in presets.PRESETS]
    assert len(ids) == len(set(ids))
    for preset_id in ids:
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]*", preset_id), preset_id


def test_get():
    first = presets.PRESETS[0]
    assert presets.get(first.id) is first
    assert presets.get("no-such-preset") is None


def test_assembler_env_only_maps_known_config_keys():
    for key in presets.ASSEMBLER_ENV:
        assert key in app_config.SCALAR_KEYS
