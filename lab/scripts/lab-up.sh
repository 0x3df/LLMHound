#!/usr/bin/env bash
# Start the isolated M0 lab: generate an untracked .env with a random password,
# pull pinned images, and wait for the CE API to answer.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$LAB_DIR"

if [ ! -f .env ]; then
    cp .env.example .env
    # Random per-lab password; .env is gitignored so no credential is committed.
    pw=$(openssl rand -hex 24 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    sed -i.bak "s/CHANGE_ME_RANDOM/$pw/" .env && rm -f .env.bak
    chmod 600 .env
    echo "wrote .env with a generated random password (kept untracked)"
fi

# Isolation guard: refuse to start if the project name was edited away from the
# lab default, so teardown can always find exactly what this lab created.
if ! grep -q '^COMPOSE_PROJECT_NAME=llmhound-m0-lab$' .env; then
    echo "refusing: COMPOSE_PROJECT_NAME must stay llmhound-m0-lab (lab isolation)" >&2
    exit 1
fi

echo "pulling pinned images (BLOODHOUND_TAG, postgres:18) ..."
# Non-fatal: images may already be cached locally; a flaky pull must not wedge
# the lab start. Compose verifies the tag exists when creating containers.
docker compose pull --quiet || echo "pull failed; continuing with local images"

docker compose up -d
echo "waiting for BloodHound CE API ..."
code=000
for i in $(seq 1 120); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${BHE_PORT:-18080}/health" || true)
    [ "$code" = "200" ] && break
    sleep 2
done
[ "$code" = "200" ] || { echo "CE API did not come up; check: docker compose logs bloodhound" >&2; exit 1; }

echo
echo "lab is up:"
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
echo
version=$(curl -s "http://127.0.0.1:${BHE_PORT:-18080}/api/version" | jq -r '.data.version // "(requires auth)"')
echo "CE version: $version"
echo "UI/API:     http://127.0.0.1:${BHE_PORT:-18080} (login admin / password in lab/.env)"
