#!/usr/bin/env bash
# Add an IP to a firewall blocklist via a generic REST API.
# Requires: FW_BASE_URL, FW_API_TOKEN. Usage: ./block_ip.sh 203.0.113.10 [--dry-run]
set -euo pipefail

ip="${1:?usage: $0 <ip> [--dry-run]}"
[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Invalid IPv4: $ip" >&2; exit 1; }

if [[ "${2:-}" == "--dry-run" ]]; then
  echo "[DRY-RUN] would block $ip"; exit 0
fi

: "${FW_BASE_URL:?set FW_BASE_URL}" "${FW_API_TOKEN:?set FW_API_TOKEN}"
curl -fsS -X POST "${FW_BASE_URL%/}/blocklist" \
  -H "Authorization: Bearer ${FW_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${ip}\",\"comment\":\"blocked by automation\"}"
echo "Blocked $ip"
