#!/usr/bin/env bash
# File: noauth_dns_recursive
# Author: strikoder (enhanced)
#
# Description:
#   Recursive DNS enumeration script that automatically enumerates all discovered hosts
#
# Usage:
#   ./noauth_dns_recursive <DNS_SERVER_IP> [DOMAIN] [subdomain_wordlist.txt]
#
# Examples:
#   ./noauth_dns_recursive 10.10.16.40
#   ./noauth_dns_recursive 10.10.16.40 htb.local
#   ./noauth_dns_recursive 10.10.16.40 htb.local subdomains.txt

set -euo pipefail

DNS_SERVER="${1:-}"
DOMAIN="${2:-}"
WORDLIST="${3:-}"
TIMEOUT=3  # DNS query timeout in seconds

if [[ -z "${DNS_SERVER}" || -z "${DOMAIN}" ]]; then
  echo "Usage: $0 <DNS_SERVER_IP> <DOMAIN> [subdomain_wordlist.txt]" >&2
  exit 1
fi

SAFE_IP="$(echo "${DNS_SERVER}" | tr '.' '_')"
OUTPUT_FILE="noauth_dns_${SAFE_IP}.log"
> "${OUTPUT_FILE}"

# Arrays to track discovered hosts and already queried hosts
declare -A DISCOVERED_HOSTS
declare -A QUERIED_HOSTS

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# Logging functions
log() {
  echo -e "$1" | tee -a "${OUTPUT_FILE}"
}

log_color() {
  echo -e "$1"
  echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "${OUTPUT_FILE}"
}

divider() {
  local line=$(yes "=" 2>/dev/null | head -n 80 | tr -d '\n')
  log_color ""
  log_color "${BOLD}${CYAN}${line}${RESET}"
  log_color "${BOLD}${YELLOW}$1${RESET}"
  log_color "${BOLD}${CYAN}${line}${RESET}"
}

section_divider() {
  local line=$(yes "-" 2>/dev/null | head -n 80 | tr -d '\n')
  log_color ""
  log_color "${BLUE}${line}${RESET}"
  log_color "${BOLD}${BLUE}▶ $1${RESET}"
  log_color "${BLUE}${line}${RESET}"
}

q() {
  local type="$1"
  local name="${2:-$DOMAIN}"
  log_color "${CYAN}$ dig @${DNS_SERVER} ${name} ${type} +noall +answer +time=${TIMEOUT} +tries=1${RESET}"
  dig @"${DNS_SERVER}" "${name}" "${type}" +noall +answer +time=${TIMEOUT} +tries=1 2>/dev/null | tee -a "${OUTPUT_FILE}" || true
}

q_short() {
  local type="$1"
  local name="${2:-$DOMAIN}"
  dig @"${DNS_SERVER}" "${name}" "${type}" +short +time=${TIMEOUT} +tries=1 2>/dev/null || true
}

# Add hostname to discovery queue
add_host() {
  local host="$1"
  # Skip if empty, IP address, or already discovered
  [[ -z "$host" ]] && return
  [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && return
  [[ -n "${DISCOVERED_HOSTS[$host]:-}" ]] && return
  
  DISCOVERED_HOSTS[$host]=1
  log_color "${GREEN}[+] Discovered new host: ${BOLD}${host}${RESET}"
}

# Recursively enumerate a hostname
enumerate_host() {
  local host="$1"
  local depth="${2:-0}"
  local max_depth=5
  
  # Skip if already queried or max depth reached
  [[ -n "${QUERIED_HOSTS[$host]:-}" ]] && return
  [[ $depth -ge $max_depth ]] && log_color "${YELLOW}[!] Max depth reached for $host${RESET}" && return
  
  QUERIED_HOSTS[$host]=1
  
  section_divider "Recursive Enumeration: ${host} (depth: ${depth})"
  
  # Query all record types
  local types=("A" "AAAA" "CNAME" "MX" "NS" "TXT")
  
  for type in "${types[@]}"; do
    local result
    result=$(q_short "$type" "$host")
    
    if [[ -n "$result" ]]; then
      log_color "${BOLD}${MAGENTA}  [${type}]${RESET} ${host}"
      local has_new_hosts=0
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        log_color "    ${CYAN}→${RESET} $line"
        
        # Extract and queue new hostnames
        case "$type" in
          "NS"|"CNAME")
            local new_host=$(echo "$line" | sed 's/\.$//')
            # Check if it's a new host before adding
            if [[ -z "${DISCOVERED_HOSTS[$new_host]:-}" ]]; then
              has_new_hosts=1
            fi
            add_host "$new_host"
            ;;
          "MX")
            local new_host=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
            if [[ -z "${DISCOVERED_HOSTS[$new_host]:-}" ]]; then
              has_new_hosts=1
            fi
            add_host "$new_host"
            ;;
        esac
      done <<< "$result"
    fi
  done
  
  # Query common SRV records for this host
  local srv_prefixes=("_ldap._tcp" "_kerberos._tcp" "_kpasswd._tcp" "_gc._tcp" "_ldap._tcp.dc._msdcs")
  for prefix in "${srv_prefixes[@]}"; do
    local srv_result
    srv_result=$(q_short "SRV" "${prefix}.${host}")
    if [[ -n "$srv_result" ]]; then
      log_color "${BOLD}${MAGENTA}  [SRV]${RESET} ${prefix}.${host}"
      echo "$srv_result" | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        log_color "    ${CYAN}→${RESET} $line"
        local srv_host=$(echo "$line" | awk '{print $4}' | sed 's/\.$//')
        add_host "$srv_host"
      done
    fi
  done
}

# Process discovery queue
process_queue() {
  local depth="${1:-0}"
  local hosts_to_process=()
  
  # Get hosts that haven't been queried yet
  for host in "${!DISCOVERED_HOSTS[@]}"; do
    [[ -z "${QUERIED_HOSTS[$host]:-}" ]] && hosts_to_process+=("$host")
  done
  
  [[ ${#hosts_to_process[@]} -eq 0 ]] && return
  
  # Process each host
  for host in "${hosts_to_process[@]}"; do
    enumerate_host "$host" "$depth"
  done
  
  # Check if new hosts were discovered
  local new_hosts=0
  for host in "${!DISCOVERED_HOSTS[@]}"; do
    [[ -z "${QUERIED_HOSTS[$host]:-}" ]] && ((new_hosts++))
  done
  
  # Recurse if new hosts found and not at max depth
  if [[ $new_hosts -gt 0 && $depth -lt 5 ]]; then
    log_color ""
    log_color "${YELLOW}[*] Found ${new_hosts} new hosts, recursing to depth $((depth + 1))${RESET}"
    process_queue $((depth + 1))
  fi
}

# ===== MAIN ENUMERATION =====

divider "DNS ENUMERATION on ${DOMAIN} via ${DNS_SERVER}"

# 1) Initial domain queries
section_divider "SOA (Start of Authority)"
q SOA

section_divider "NS (Authoritative Nameservers)"
ns_output=$(q_short "NS")
echo "$ns_output" | tee -a "${OUTPUT_FILE}"
while IFS= read -r ns; do
  [[ -n "$ns" ]] && add_host "$(echo "$ns" | sed 's/\.$//')"
done <<< "$ns_output"

section_divider "ANY (may be restricted on hardened servers)"
q ANY

section_divider "A (IPv4)"
q A

section_divider "AAAA (IPv6)"
q AAAA

section_divider "CNAME (Aliases)"
cname_output=$(q_short "CNAME")
echo "$cname_output" | tee -a "${OUTPUT_FILE}"
while IFS= read -r cname; do
  [[ -n "$cname" ]] && add_host "$(echo "$cname" | sed 's/\.$//')"
done <<< "$cname_output"

section_divider "MX (Mail Exchangers)"
mx_output=$(q_short "MX")
echo "$mx_output" | tee -a "${OUTPUT_FILE}"
while IFS= read -r mx; do
  [[ -z "$mx" ]] && continue
  mx_host=$(echo "$mx" | awk '{print $NF}' | sed 's/\.$//')
  [[ -n "$mx_host" ]] && add_host "$mx_host"
done <<< "$mx_output"

section_divider "TXT (SPF/DMARC/Notes)"
q TXT

# 2) AD SRV records
section_divider "SRV Records (common AD services if applicable)"
for srv in "_ldap._tcp" "_kerberos._tcp" "_kpasswd._tcp" "_ldap._tcp.dc._msdcs"; do
  srv_output=$(q_short "SRV" "${srv}.${DOMAIN}")
  if [[ -n "$srv_output" ]]; then
    log_color "${CYAN}$ dig @${DNS_SERVER} ${srv}.${DOMAIN} SRV +short${RESET}"
    echo "$srv_output" | tee -a "${OUTPUT_FILE}"
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      srv_host=$(echo "$line" | awk '{print $4}' | sed 's/\.$//')
      [[ -n "$srv_host" ]] && add_host "$srv_host"
    done <<< "$srv_output"
  fi
done

# 3) Zone transfer
section_divider "AXFR (Zone Transfer Attempt)"
log_color "${CYAN}$ dig AXFR ${DOMAIN} @${DNS_SERVER}${RESET}"
axfr_output=$(timeout 10 dig AXFR "${DOMAIN}" @"${DNS_SERVER}" +time=5 +tries=1 2>&1 || true)
echo "$axfr_output" | tee -a "${OUTPUT_FILE}"

# Parse AXFR results
if [[ "$axfr_output" != *"Transfer failed"* && "$axfr_output" != *"connection timed out"* && "$axfr_output" != *"communications error"* ]]; then
  while IFS= read -r line; do
    if [[ "$line" =~ ^([a-zA-Z0-9._-]+)\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+(A|AAAA|NS|CNAME|MX) ]]; then
      host=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
      type=$(echo "$line" | awk '{print $4}')
      
      [[ -n "$host" ]] && add_host "$host"
      
      # Also add targets of NS, CNAME, MX records
      if [[ "$type" =~ ^(NS|CNAME)$ ]]; then
        target=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
        [[ -n "$target" ]] && add_host "$target"
      elif [[ "$type" == "MX" ]]; then
        target=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')
        [[ -n "$target" ]] && add_host "$target"
      fi
    fi
  done <<< "$axfr_output"
else
  log_color "${RED}[!] AXFR failed or not allowed${RESET}"
fi

# 4) Reverse PTR
section_divider "Reverse (PTR) of DNS server"
log_color "${CYAN}$ dig -x ${DNS_SERVER} @${DNS_SERVER} +noall +answer${RESET}"
ptr_output=$(dig -x "${DNS_SERVER}" @"${DNS_SERVER}" +short +time=${TIMEOUT} +tries=1 2>/dev/null || true)
echo "$ptr_output" | tee -a "${OUTPUT_FILE}"
[[ -n "$ptr_output" ]] && add_host "$(echo "$ptr_output" | sed 's/\.$//')"

# 5) Brute subdomains
if [[ -n "${WORDLIST:-}" && -r "${WORDLIST}" ]]; then
  section_divider "Subdomain Brute (wordlist: ${WORDLIST})"
  while IFS= read -r sub || [[ -n "$sub" ]]; do
    [[ -z "$sub" || "$sub" =~ ^# ]] && continue
    
    fqdn="${sub}.${DOMAIN}"
    for TYPE in A AAAA; do
      result=$(q_short "$TYPE" "$fqdn")
      if [[ -n "$result" ]]; then
        echo "$result" | awk -v s="${fqdn}" '{print s " -> " $0}' | tee -a "${OUTPUT_FILE}"
        add_host "$fqdn"
      fi
    done
  done < <(sed 's/\r$//' "${WORDLIST}")
fi

# 6) Recursive enumeration
if [[ ${#DISCOVERED_HOSTS[@]} -gt 0 ]]; then
  divider "RECURSIVE ENUMERATION OF DISCOVERED HOSTS"
  log_color "${YELLOW}[*] Starting recursive enumeration of ${BOLD}${#DISCOVERED_HOSTS[@]}${RESET}${YELLOW} discovered hosts${RESET}"
  process_queue 0
fi

# 7) Summary
divider "ENUMERATION SUMMARY"
log_color "${BOLD}${GREEN}[+] Total hosts discovered: ${#DISCOVERED_HOSTS[@]}${RESET}"
log_color "${BOLD}${GREEN}[+] Total hosts enumerated: ${#QUERIED_HOSTS[@]}${RESET}"

if [[ ${#DISCOVERED_HOSTS[@]} -gt 0 ]]; then
  log_color ""
  log_color "${BOLD}${YELLOW}[+] All discovered hosts:${RESET}"
  for host in "${!DISCOVERED_HOSTS[@]}"; do
    log_color "  ${CYAN}•${RESET} ${host}"
  done
fi

log_color ""
log_color "${BOLD}${MAGENTA}[+] NS Records:${RESET}"
q_short "NS" | while IFS= read -r line; do
  [[ -n "$line" ]] && log_color "  ${CYAN}→${RESET} $line"
done

log_color ""
log_color "${BOLD}${MAGENTA}[+] MX Records:${RESET}"
mx_summary=$(q_short "MX")
if [[ -n "$mx_summary" ]]; then
  echo "$mx_summary" | while IFS= read -r line; do
    log_color "  ${CYAN}→${RESET} $line"
  done
else
  log_color "  ${YELLOW}(none)${RESET}"
fi

log_color ""
log_color "${BOLD}${MAGENTA}[+] TXT Records:${RESET}"
q_short "TXT" | while IFS= read -r line; do
  [[ -n "$line" ]] && log_color "  ${CYAN}→${RESET} $line"
done

log_color ""
log_color "${BOLD}${MAGENTA}[+] A Records (root):${RESET}"
a_summary=$(q_short "A")
if [[ -n "$a_summary" ]]; then
  echo "$a_summary" | while IFS= read -r line; do
    log_color "  ${CYAN}→${RESET} $line"
  done
else
  log_color "  ${YELLOW}(none)${RESET}"
fi

log_color ""
line=$(yes "=" 2>/dev/null | head -n 80 | tr -d '\n')
log_color "${BOLD}${GREEN}${line}${RESET}"
log_color "${BOLD}${GREEN}✓ Recursive DNS enumeration complete!${RESET}"
log_color "${BOLD}${GREEN}✓ Results saved to: ${OUTPUT_FILE}${RESET}"
log_color "${BOLD}${GREEN}${line}${RESET}"
