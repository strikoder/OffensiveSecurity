#!/usr/bin/env bash
# File: noauth_ldap
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
#   ./noauth_ldap <IP> <domain> [ldap|ldaps]
#
# Arguments:
#   <IP>        Target Domain Controller IP or hostname
#   <domain>    Full domain name (e.g. "support.htb")
#   [protocol]  Optional: "ldap" (default) or "ldaps"
#
# Examples:
#   ./noauth_ldap 10.129.230.181  support.htb
#   ./noauth_ldap 10.129.230.181  support.htb -ldaps
#
# Output (saved in results_ldap_auth/):
#   ldap.txt          -> Full ldapsearch output
#   ldap_info_ctx.txt -> Context for entries with 'info:' attribute
#   ldap_pwdnotreqd.txt -> Context for userAccountControl ending in 32
#
# Notes:
#   - The script automatically converts <username> into <username>@<domain> for binding.
#   - Defaults to ldap if no protocol is given.
#   - All ldapsearch output and errors are shown on console via tee and also written to files.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <IP> <domain> -[ldap|ldaps]"
  exit 1
fi

IP="$1"
DOMAIN="$2"
PROTO="${3:-ldap}"

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


BASEDN=$(echo "$DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s",$i,(i<NF?",":""); print ""}')
URL="${PROTO}://${IP}"

OUTDIR="results_noauth_ldap"
mkdir -p "$OUTDIR"

OUT_MAIN="${OUTDIR}/ldap.txt"
OUT_INFO="${OUTDIR}/ldap_info_ctx.txt"
OUT_PWDNR="${OUTDIR}/ldap_pwdnotreqd.txt"
OUT_CASCADE="${OUTDIR}/ldap_cascade_pwd.txt"
NXC_OUT="${OUTDIR}/ldap_nxc_users.txt"
NXC_USERS="${OUTDIR}/usernames.txt"
NXC_USERS_DESC="${OUTDIR}/users_with_descriptions.txt"

echo "==============================================================="
echo "[*] Running ldapsearch on $URL ..."
echo "==============================================================="
ldapsearch -LLL -x -H "$URL" -b "$BASEDN" "(objectClass=user)" | tee "$OUT_MAIN"

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
echo "[*] Running NetExec LDAP null/guest --users (if allowed)"
echo "==============================================================="

for USER in "" "guest"; do
  echo "[*] Running: nxc ldap ${IP} -u \"${USER}\" -p \"\" --users"

  CMD=(nxc ldap "${IP}" -u "${USER}" -p "" --users)
  OUTPUT="$("${CMD[@]}" 2>/dev/null || true)"

  if echo "${OUTPUT}" | grep -q -- '-Username-'; then
    echo "${OUTPUT}" | tee -a "${NXC_OUT}"

    echo "${OUTPUT}" \
    | awk '
      $5 == "-Username-" { in_table=1; next }
      in_table && NF >= 6 {
        username = $5
        description = ""

        if (NF > 9) {
          for (i = 10; i <= NF; i++) {
            description = description $i " "
          }
          gsub(/[ \t]+$/, "", description)
          print username " | " description >> "'"${NXC_USERS_DESC}"'"
          print username >> "'"${NXC_USERS}"'"
        } else {
          print username >> "'"${NXC_USERS}"'"
        }
      }'
  else
    echo "[-] No output or access denied for user '${USER}'" | tee -a "${NXC_OUT}"
  fi
done

echo "==============================================================="
echo "[*] Done. Results saved in $OUTDIR/"
echo "==============================================================="
