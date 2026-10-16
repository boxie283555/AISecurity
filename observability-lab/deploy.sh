#!/usr/bin/env bash
set -euo pipefail

VM_HOST="${1:-192.168.20.170}"
VM_USER="${2:-root}"
REMOTE_DIR="${3:-/opt/observability-lab}"

echo "Deploying to ${VM_USER}@${VM_HOST}:${REMOTE_DIR}"

ssh "${VM_USER}@${VM_HOST}" "mkdir -p '${REMOTE_DIR}'"
tar czf - --exclude='.git' -C "$(dirname "$0")" . | ssh "${VM_USER}@${VM_HOST}" "tar xzf - -C '${REMOTE_DIR}'"
ssh "${VM_USER}@${VM_HOST}" "cd '${REMOTE_DIR}' && docker compose up -d"

echo "Done. Grafana: http://${VM_HOST}:3000"
