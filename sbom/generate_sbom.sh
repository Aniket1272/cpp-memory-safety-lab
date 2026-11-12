#!/usr/bin/env bash
# Generate CycloneDX and SPDX SBOMs from the sample manifest in this folder and,
# if Grype is installed and can download its database, match components to known CVEs.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v syft >/dev/null; then
  echo "syft not found. Install: https://github.com/anchore/syft#installation" >&2
  exit 1
fi

syft dir:. -q -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
echo "Wrote sbom.cdx.json and sbom.spdx.json"

python3 - <<'PY'
import json
bom = json.load(open("sbom.cdx.json"))
print(f"CycloneDX {bom.get('specVersion')}: components found")
for c in bom.get("components", []):
    if c.get("type") == "library":
        print(f"  {c['name']} {c.get('version')}  purl={c.get('purl')}")
PY

if command -v grype >/dev/null; then
  echo "--- grype (needs network access to download its vulnerability database)"
  grype sbom:sbom.cdx.json || echo "grype failed (offline, or database unavailable)"
else
  echo "grype not installed; skipping vulnerability matching"
fi
