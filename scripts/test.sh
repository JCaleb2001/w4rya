#!/usr/bin/env bash
# Run the api test suite.
#
#   ./scripts/test.sh              all tests
#   ./scripts/test.sh -k setup     pytest args pass straight through
#   ./scripts/test.sh -x -q
#
# Mounts services/api read-only over the existing image instead of rebuilding,
# so editing a test is instant. The suite needs no database and no network:
# see the comment at the top of services/api/tests/conftest.py.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE=w4rya-api:latest

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  exec docker run --rm \
    -v "$PWD/services/api:/app:ro" \
    -e W4RYA_SECRET_KEY=test-secret-not-a-real-key \
    -e TIMESCALE='postgres://w4rya@127.0.0.1:1/w4rya' \
    -w /app "$IMAGE" \
    python -m pytest tests/ -p no:cacheprovider "$@"
fi

# No image yet: fall back to the running container, which has the code baked in.
COMPOSE_FILE="$(awk -F= '/^W4RYA_COMPOSE_FILE=/{print $2}' .env 2>/dev/null | tail -1)"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
echo "note: $IMAGE not built yet — running inside the live api container instead." >&2
exec docker compose -f "$COMPOSE_FILE" exec -T api \
  python -m pytest /app/tests -p no:cacheprovider "$@"
