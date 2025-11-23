#!/usr/bin/env bash
# File: noauth
# Author: strikoder
#
# Description:
#   Enhanced DNS enumeration script that works with or without a known domain.
#
# Usage:
#   ./noauth_dns <DNS_SERVER_IP> [DOMAIN] [subdomain_wordlist.txt]
#
# Examples:
#   ./noauth_dns 10.10.16.40
#   ./noauth_dns 10.10.16.40 htb.local
#   ./noauth_dns 10.10.16.40 htb.local subdomains.txt
#
# What it does:
#   1) SOA and NS queries (authority, nameservers)
#   2) ANY query (may be restricted)
#   3) Core record types: A, AAAA, CNAME, MX, TXT
#   4) Common AD SRV records (_ldap, _kerberos, _kpasswd, _msdcs)
#   5) Zone transfer attempt (AXFR)
#   6) Reverse lookup (PTR) for the DNS server
#   7) Brute-force subdomains with provided wordlist
#   8) Prints a short summary (NS, MX, TXT, A)
#
# Output:
#   Results are printed directly to console.
#   If a wordlist is supplied, discovered subdomains with resolved IPs are shown.


set -euo pipefail

DNS_SERVER="${1:-}"
DOMAIN="${2:-}"
WORDLIST="${3:-}"

if [[ -z "${DNS_SERVER}" || -z "${DOMAIN}" ]]; then
  echo "Usage: $0 <DNS_SERVER_IP> <DOMAIN> [subdomain_wordlist.txt]" >&2
  exit 1
fi

SAFE_IP="$(echo "${DNS_SERVER}" | tr '.' '_')"
OUTPUT_FILE="noauth_dns_${SAFE_IP}.log"
> "${OUTPUT_FILE}"

log() {
  echo "$1" | tee -a "${OUTPUT_FILE}"
}

divider() {
  log ""
  log "===== $1 ====="
}

q() {
  local type="$1"
  local name="${2:-$DOMAIN}"
  log "\$ dig @${DNS_SERVER} ${name} ${type} +noall +answer"
  dig @"${DNS_SERVER}" "${name}" "${type}" +noall +answer | tee -a "${OUTPUT_FILE}" || true
}

# 0) Banner
divider "DNS ENUM on ${DOMAIN} via ${DNS_SERVER}"

# 1) SOA and NS
divider "SOA (Start of Authority)"
q SOA
divider "NS (Authoritative Nameservers)"
q NS

# 2) ANY
divider "ANY (may be restricted on hardened servers)"
q ANY

# 3) Core record types
divider "A (IPv4)"
q A
divider "AAAA (IPv6)"
q AAAA
divider "CNAME (Aliases)"
q CNAME
divider "MX (Mail Exchangers)"
q MX
divider "TXT (SPF/DMARC/Notes)"
q TXT

# 4) AD SRV records
divider "SRV Records (common AD services if applicable)"
q SRV "_ldap._tcp.${DOMAIN}"
q SRV "_kerberos._tcp.${DOMAIN}"
q SRV "_kpasswd._tcp.${DOMAIN}"
q SRV "_ldap._tcp.dc._msdcs.${DOMAIN}"

# 5) Zone transfer
divider "AXFR (Zone Transfer Attempt)"
log "\$ dig AXFR ${DOMAIN} @${DNS_SERVER}"
dig AXFR "${DOMAIN}" @"${DNS_SERVER}" +nocookie +nsid | tee -a "${OUTPUT_FILE}" || log "[!] AXFR failed or not allowed."

# 6) Reverse PTR
divider "Reverse (PTR) of DNS server"
REV_ARPA="$(printf "%s" "${DNS_SERVER}" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')"
log "\$ dig -x ${DNS_SERVER} @${DNS_SERVER} +noall +answer"
dig -x "${DNS_SERVER}" @"${DNS_SERVER}" +noall +answer | tee -a "${OUTPUT_FILE}" || true

# 7) Brute subdomains
if [[ -n "${WORDLIST:-}" && -r "${WORDLIST}" ]]; then
  divider "Subdomain Brute (wordlist: ${WORDLIST})"
  while IFS= read -r sub || [[ -n "$sub" ]]; do
    [[ -z "$sub" || "$sub" =~ ^# ]] && continue
    for TYPE in A AAAA; do
      dig @"${DNS_SERVER}" "${sub}.${DOMAIN}" "${TYPE}" +short \
        | awk -v s="${sub}" -v d="${DOMAIN}" '{print s "." d " -> " $0}' \
        | tee -a "${OUTPUT_FILE}"
    done
  done < <(sed 's/\r$//' "${WORDLIST}")
fi

# 8) Summary
divider "Summary (quick hits)"
log "[+] NS:"
dig @"${DNS_SERVER}" "${DOMAIN}" NS +short | tee -a "${OUTPUT_FILE}" || true

log "[+] MX:"
dig @"${DNS_SERVER}" "${DOMAIN}" MX +short | tee -a "${OUTPUT_FILE}" || true

log "[+] TXT:"
dig @"${DNS_SERVER}" "${DOMAIN}" TXT +short | tee -a "${OUTPUT_FILE}" || true

log "[+] A (root):"
dig @"${DNS_SERVER}" "${DOMAIN}" A +short | tee -a "${OUTPUT_FILE}" || true

log ""
log "[✓] DNS enumeration complete. Results saved to: ${OUTPUT_FILE}"
