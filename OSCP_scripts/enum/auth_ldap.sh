#!/usr/bin/env bash
# File: auth_ldap
# Author: strikoder
#
# Description:
#   Run an authenticated LDAP/LDAPS search against an Active Directory domain.
#   Dumps all user objects with selected attributes, then extracts:
#     - Users Description
#     - Users that have the "info" attribute (with context lines)
#     - Users with userAccountControl values ending in 32 (often means "Password Not Required")
#
# Usage:
#   ./auth_ldap <IP> <username> <password> <domain> [ldap|ldaps]
#
# Arguments:
#   <IP>        Target Domain Controller IP or hostname
#   <username>  Account name (without domain, e.g. "ldap")
#   <password>  Account password (quote if it has special chars)
#   <domain>    Full domain name (e.g. "support.htb")
#   [protocol]  Optional: "ldap" (default) or "ldaps"
#
# Examples:
#   ./auth_ldap 10.129.230.181 ldap 'P@ssw0rd!' support.htb
#   ./auth_ldap 10.129.230.181 ldap 'P@ssw0rd!' support.htb -ldaps
#
# Output (saved in results_ldap_auth/):
#   ldap_<IP>_<timestamp>.txt          -> Full ldapsearch output
#   ldap_info_ctx_<IP>_<timestamp>.txt -> Context for entries with 'info:' attribute
#   ldap_pwdnotreqd_<IP>_<timestamp>.txt -> Context for userAccountControl ending in 32
#
# Notes:
#   - The script automatically converts <username> into <username>@<domain> for binding.
#   - Defaults to ldap if no protocol is given.
#   - All ldapsearch output and errors are shown on console via tee and also written to files.

set -uo pipefail

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <IP> <username> <password> <domain> -[ldap|ldaps]"
  exit 1
fi

IP="$1"
USER="$2"
PASS="$3"
DOMAIN="$4"
PROTO="${5:-ldap}"

if [[ "$PROTO" == "-ldap" ]]; then
  PROTO="ldap"
elif [[ "$PROTO" == "-ldaps" ]]; then
  PROTO="ldaps"
elif [[ "$PROTO" != "ldap" && "$PROTO" != "ldaps" ]]; then
  echo "Protocol must be ldap or ldaps"
  exit 1
fi


echo "==============================================================="
echo "[*] Protocol: $PROTO (default is 'ldap', pass 'ldaps' if needed)"


BINDUSER="${USER}@${DOMAIN}"
BASEDN=$(echo "$DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s",$i,(i<NF?",":""); print ""}')
URL="${PROTO}://${IP}"

OUTDIR="results_auth_ldap"
mkdir -p "$OUTDIR"

OUT_MAIN="${OUTDIR}/ldap.txt"
OUT_INFO="${OUTDIR}/ldap_info_ctx.txt"
OUT_PWDNR="${OUTDIR}/ldap_pwdnotreqd.txt"
OUT_CASCADE="${OUTDIR}/ldap_cascade_pwd.txt"

echo "==============================================================="
echo "[*] Running ldapsearch on $URL with $BINDUSER ..."
echo "==============================================================="
ldapsearch -LLL -x -H "$URL" -D "$BINDUSER" -w "$PASS" -b "$BASEDN" "(objectClass=user)" | tee "$OUT_MAIN"

echo "==============================================================="
echo "[*] Grepping 'info:' with context (-B1 -A2)..."
echo "==============================================================="
grep -i -B1 -A2 '^info:' "$OUT_MAIN" | tee "$OUT_INFO" || true

echo "==============================================================="
echo "[*] Grepping UAC entries aka users with no password or have different than the passpolicy ending in 32 (-B1 -A2)..."
echo "==============================================================="
grep -E -B1 -A2 '^userAccountControl:[[:space:]]*[0-9]*32$' "$OUT_MAIN" | tee "$OUT_PWDNR" || true

echo "==============================================================="
echo "[*] Extracting cascadeLegacy creds -> $OUT_CASCADE"
echo "==============================================================="
awk 'BEGIN{IGNORECASE=1}
     /^$/ { if(u!="" && p!=""){print u ":" p}; u=""; p=""; next }
     /^sAMAccountName:[[:space:]]*/ { sub(/^sAMAccountName:[[:space:]]*/,""); u=$0 }
     /cascadeLegacy/ && /:/ { sub(/^[^:]*:[[:space:]]*/,""); p=$0 }
     END { if(u!="" && p!=""){print u ":" p} }' "$OUT_MAIN" \
| tee "$OUT_CASCADE" || true

echo "==============================================================="
echo "[*] Command: nxc ldap ${IP} -u '${USER}' -p '${PASS}' -d '${DOMAIN}'--users & -M laps & -M adcs"
echo "==============================================================="

nxc ldap "${IP}" -u "${USER}" -p "${PASS}" -d "${DOMAIN}" --users  2>/dev/null 
nxc ldap "${IP}" -u "${USER}" -p "${PASS}" -d "${DOMAIN}" -M laps  2>/dev/null 
nxc ldap "${IP}" -u "${USER}" -p "${PASS}" -d "${DOMAIN}" -M adcs  2>/dev/null 



echo "==============================================================="
echo "[*] Done. Results saved in $OUTDIR/"
echo "==============================================================="
echo "    - Full dump: $OUT_MAIN"
echo "    - Info ctx:  $OUT_INFO"
echo "    - UAC=...32: $OUT_PWDNR"
echo "    - For full results check: $OUTDIR/"
