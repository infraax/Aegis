#!/usr/bin/env bash
# Download the MITRE ATT&CK Enterprise STIX bundle.
# Run once during initial setup or to refresh the dataset.
#
# Usage: ./scripts/download-attack-stix.sh
# Output: /opt/aegis/data/enterprise-attack.json (~20MB)
#
# Source: https://github.com/mitre-attack/attack-stix-data

set -euo pipefail

DATA_DIR="${ATTACK_DATA_DIR:-/opt/aegis/data}"
OUT_FILE="${DATA_DIR}/enterprise-attack.json"
STIX_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

echo "[attack-stix] Creating data directory: ${DATA_DIR}"
mkdir -p "${DATA_DIR}"

echo "[attack-stix] Downloading ATT&CK Enterprise STIX bundle..."
curl -fsSL --retry 3 --retry-delay 2 \
  -o "${OUT_FILE}.tmp" \
  "${STIX_URL}"

# Verify it's valid JSON before replacing the live file
if python3 -c "import json, sys; json.load(sys.stdin)" < "${OUT_FILE}.tmp"; then
  mv "${OUT_FILE}.tmp" "${OUT_FILE}"
  TECHNIQUE_COUNT=$(python3 -c "
import json
with open('${OUT_FILE}') as f:
    bundle = json.load(f)
count = sum(1 for o in bundle['objects'] if o.get('type') == 'attack-pattern')
print(count)
")
  echo "[attack-stix] Done. ${TECHNIQUE_COUNT} techniques loaded."
  echo "[attack-stix] Saved to: ${OUT_FILE}"
else
  rm -f "${OUT_FILE}.tmp"
  echo "[attack-stix] ERROR: downloaded file is not valid JSON — aborting"
  exit 1
fi
