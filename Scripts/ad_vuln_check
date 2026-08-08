#!/usr/bin/env bash
# ad_vuln_simple_opt.sh
# Usage: sudo ./ad_vuln_simple_opt.sh <DC-hostname> <DC-ip>
set -euo pipefail

DC_HOST="${1:-}"
DC_IP="${2:-}"
if [[ -z "$DC_HOST" || -z "$DC_IP" ]]; then
  echo "Usage: $0 <DC-hostname> <DC-ip>"
  exit 2
fi

# 1) Zerologon check, clone once to /opt if missing
REPO_DIR="/opt/CVE-2020-1472"
ZEROSCRIPT="$REPO_DIR/zerologon_tester.py"

if [[ -f "$ZEROSCRIPT" ]]; then
  echo "zerologon tester found at $ZEROSCRIPT"
else
  echo "cloning zerologon tester to $REPO_DIR"
  # create /opt if needed and clone as root if necessary
  git clone https://github.com/SecuraBV/CVE-2020-1472 "$REPO_DIR"
fi

echo "running zerologon tester..."
python3 "$ZEROSCRIPT" "$DC_HOST" "$DC_IP" || true

# 2) PrintNightmare surface check via rpcdump.py (Impacket)
echo
echo "Running rpcdump.py against ${DC_IP} to detect if the system vulnearable to PrintNightmare..."

rpcdump.py @"${DC_IP}" | egrep 'MS-RPRN|MS-PAR' || true

echo
echo "if Print System Asynchronous Protocol and Print System Remote Protocol are exposed on the target => Target VULNEARABLE."
