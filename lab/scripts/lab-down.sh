#!/usr/bin/env bash
# Tear down ONLY this lab's Compose resources (project llmhound-m0-lab):
# containers, networks, and labeled volumes. Never prunes Docker globally.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$LAB_DIR"

if [ ! -f .env ] || ! grep -q '^COMPOSE_PROJECT_NAME=llmhound-m0-lab$' .env; then
    echo "refusing: .env missing or project name changed; nothing will be removed" >&2
    exit 1
fi

# -v removes the lab's named volumes (labeled with the Compose project).
# This project only created: llmhound-m0-lab_postgres-data and its network.
docker compose down -v --remove-orphans

# Credentials and tokens live only in the untracked runtime dir; remove it.
rm -rf "$LAB_DIR/.runtime"
rm -f "$LAB_DIR/.env"

echo "lab torn down (only project llmhound-m0-lab resources removed)"
