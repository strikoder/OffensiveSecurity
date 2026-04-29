#!/usr/bin/env bash
#
# noauth_smb.sh - Comprehensive Unauthenticated SMB Enumeration
# Author: strikoder
#
# Description:
#   Performs comprehensive SMB enumeration without credentials.
#   Saves critical data to files while displaying all output live.
#
# Usage: ./noauth_smb.sh <IP>

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Config
readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

if [[ $# -ne 1 ]]; then
    echo -e "${RED}[!] Usage: ${SCRIPT_NAME} <IP>${NC}" >&2
    exit 1
fi

readonly TARGET_IP="$1"
readonly OUT_DIR="results_noauth_smb/${TARGET_IP}_${TIMESTAMP}"
readonly DOWNLOAD_DIR="${OUT_DIR}/downloads"

mkdir -p "${OUT_DIR}" "${DOWNLOAD_DIR}"

# Output Files
readonly LOG_SHARES="${OUT_DIR}/shares.log"
readonly LOG_USERS="${OUT_DIR}/users.log"
readonly LOG_GROUPS="${OUT_DIR}/groups.log"
readonly LOG_POLICY="${OUT_DIR}/password_policy.log"
readonly LOG_RPC="${OUT_DIR}/rpcclient.log"
readonly LOG_VULNS="${OUT_DIR}/vulnerabilities.log"
readonly LOG_NMAP="${OUT_DIR}/nmap.log"
readonly LOG_ENUM4LINUX="${OUT_DIR}/enum4linux.log"
readonly USERS_FILE="${OUT_DIR}/users.txt"

# Helpers
log_warning() { echo -e "${YELLOW}[!] $*${NC}"; }
log_error()   { echo -e "${RED}[-] $*${NC}" >&2; }
log_info()    { echo -e "${GREEN}[+] $*${NC}"; }
log_step()    { echo -e "${BLUE}[>] $*${NC}"; }

section_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title} - 2) / 2 ))
    echo
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo -e "${CYAN}$(printf ' %.0s' $(seq 1 $padding))${title}${NC}"
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo
}


# ╔══════════════════════════════════════════════════════════╗
# ║                  1. SHARE ENUMERATION                    ║
# ╚══════════════════════════════════════════════════════════╝
enum_shares() {
    section_header "SHARE ENUMERATION"

    log_step "smbclient - list shares"
    smbclient -N -L "\\\\${TARGET_IP}\\" 2>&1 | tee -a "${LOG_SHARES}" \
        || log_warning "smbclient null session failed"

    echo >> "${LOG_SHARES}"

    log_step "netexec - share listing (guest)"
    nxc smb "${TARGET_IP}" -u "guest" -p "" --shares 2>&1 | tee -a "${LOG_SHARES}" \
        || log_warning "nxc --shares (guest) failed"

    log_step "netexec - share listing (null)"
    nxc smb "${TARGET_IP}" -u "" -p "" --shares 2>&1 | tee -a "${LOG_SHARES}" \
        || log_warning "nxc --shares (null) failed"

    echo >> "${LOG_SHARES}"

    log_step "smbmap - share permissions (guest)"
    smbmap -H "${TARGET_IP}" -u "guest" 2>&1 | tee -a "${LOG_SHARES}" \
        || log_warning "smbmap (guest) failed"

    log_step "smbmap - share permissions (null)"
    smbmap -H "${TARGET_IP}" -u "" -p "" 2>&1 | tee -a "${LOG_SHARES}" \
        || log_warning "smbmap (null) failed"
}


# ╔══════════════════════════════════════════════════════════╗
# ║                  2. USER ENUMERATION                     ║
# ╚══════════════════════════════════════════════════════════╝
enum_users() {
    section_header "USER ENUMERATION"

    log_step "netexec - --users (guest)"
    nxc smb "${TARGET_IP}" -u "guest" -p "" --users 2>&1 | tee -a "${LOG_USERS}" \
        || log_warning "nxc --users (guest) failed"

    log_step "netexec - --users (null)"
    nxc smb "${TARGET_IP}" -u "" -p "" --users 2>&1 | tee -a "${LOG_USERS}" \
        || log_warning "nxc --users (null) failed"

    log_step "netexec - RID brute (guest)"
    nxc smb "${TARGET_IP}" -u "guest" -p "" --rid-brute 2>&1 | tee -a "${LOG_USERS}" \
        || log_warning "RID brute (guest) failed"

    log_step "netexec - RID brute (null)"
    nxc smb "${TARGET_IP}" -u "" -p "" --rid-brute 2>&1 | tee -a "${LOG_USERS}" \
        || log_warning "RID brute (null) failed"

    log_step "rpcclient - enumdomusers / querydispinfo"
    {
        echo "enumdomusers"
        echo "querydispinfo"
    } | rpcclient -U "" -N "${TARGET_IP}" 2>&1 | tee -a "${LOG_USERS}" \
        || log_warning "rpcclient user enum failed"

    if [[ -f "${LOG_USERS}" ]]; then
        awk '{print $5}' "${LOG_USERS}" | sed '1,3d;$d' | sort -u > "${USERS_FILE}" 2>/dev/null || true
        if [[ -s "${USERS_FILE}" ]]; then
            log_info "Extracted $(wc -l < "${USERS_FILE}") username(s) → ${USERS_FILE}"
        fi
    fi
}


# ╔══════════════════════════════════════════════════════════╗
# ║                  3. GROUP ENUMERATION                    ║
# ╚══════════════════════════════════════════════════════════╝
enum_groups() {
    section_header "GROUP ENUMERATION"

    log_step "rpcclient - enumdomgroups / enumalsgroups"
    {
        echo "enumdomgroups"
        echo "enumalsgroups builtin"
        echo "enumalsgroups domain"
    } | rpcclient -U "" -N "${TARGET_IP}" 2>&1 | tee -a "${LOG_GROUPS}" \
        || log_warning "rpcclient group enum failed"
}


# ╔══════════════════════════════════════════════════════════╗
# ║               4. DOMAIN / HOST INFO                      ║
# ╚══════════════════════════════════════════════════════════╝
enum_host_info() {
    section_header "DOMAIN / HOST INFO"

    log_step "rpcclient - srvinfo / lsaquery / enumdomains / querydominfo"
    {
        echo "srvinfo"
        echo "lsaquery"
        echo "enumdomains"
        echo "querydominfo"
    } | rpcclient -U "" -N "${TARGET_IP}" 2>&1 | tee -a "${LOG_RPC}" \
        || log_warning "rpcclient host info failed"

    log_step "netexec - host info (guest)"
    nxc smb "${TARGET_IP}" -u "guest" -p "" 2>&1 | tee -a "${LOG_RPC}" || true

    log_step "netexec - host info (null)"
    nxc smb "${TARGET_IP}" -u "" -p "" 2>&1 | tee -a "${LOG_RPC}" || true
}


# ╔══════════════════════════════════════════════════════════╗
# ║               5. PASSWORD POLICY                         ║
# ╚══════════════════════════════════════════════════════════╝
enum_password_policy() {
    section_header "PASSWORD POLICY"

    log_step "netexec - --pass-pol (guest)"
    nxc smb "${TARGET_IP}" -u "guest" -p "" --pass-pol 2>&1 | tee -a "${LOG_POLICY}" \
        || log_warning "nxc --pass-pol (guest) failed"

    log_step "netexec - --pass-pol (null)"
    nxc smb "${TARGET_IP}" -u "" -p "" --pass-pol 2>&1 | tee -a "${LOG_POLICY}" \
        || log_warning "nxc --pass-pol (null) failed"

    log_step "rpcclient - getdompwinfo / passpol"
    {
        echo "getdompwinfo"
        echo "passpol"
    } | rpcclient -U "" -N "${TARGET_IP}" 2>&1 | tee -a "${LOG_POLICY}" \
        || log_warning "rpcclient password policy failed"
}


# ╔══════════════════════════════════════════════════════════╗
# ║               6. NMAP SMB SCRIPTS                        ║
# ╚══════════════════════════════════════════════════════════╝
enum_nmap() {
    section_header "NMAP SMB SCRIPTS"

    nmap -Pn -p445 -sV \
        --script "smb-security-mode,smb-protocols,smb2-capabilities" \
        "${TARGET_IP}" 2>&1 | tee "${LOG_NMAP}" \
        || log_warning "Nmap scan failed"
}


# ╔══════════════════════════════════════════════════════════╗
# ║               7. ENUM4LINUX-NG                           ║
# ╚══════════════════════════════════════════════════════════╝
enum_enum4linux() {
    section_header "ENUM4LINUX-NG"

    enum4linux-ng -A "${TARGET_IP}" 2>&1 | tee "${LOG_ENUM4LINUX}" \
        || log_warning "enum4linux-ng failed"
}


# ╔══════════════════════════════════════════════════════════╗
# ║               8. VULNERABILITY CHECKS                    ║
# ╚══════════════════════════════════════════════════════════╝
enum_vulnerabilities() {
    section_header "VULNERABILITY CHECKS"

    local modules=(
        ms17-010
        smbghost
        enum_av
        enum_ca
        gpp_autologin
        gpp_password
        spooler
        webdav
        ioxidresolver
    )

    for module in "${modules[@]}"; do
        log_step "Module: ${module}"
        nxc smb "${TARGET_IP}" -u "guest" -p "" -M "${module}" 2>&1 | tee -a "${LOG_VULNS}" || true
        nxc smb "${TARGET_IP}" -u "" -p "" -M "${module}" 2>&1 | tee -a "${LOG_VULNS}" || true
        echo >> "${LOG_VULNS}"
    done
}


# Summary + manual vuln commands
print_vuln_commands() {
    section_header "MANUAL VULNERABILITY COMMANDS (run individually)"

    echo -e "${YELLOW}Copy-paste these individually as needed:${NC}"
    echo

    echo -e "${CYAN}# PrintNightmare${NC}"
    echo "nxc smb ${TARGET_IP} -u 'guest' -p '' -M printnightmare"
    echo "nxc smb ${TARGET_IP} -u '' -p '' -M printnightmare"
    echo

    echo -e "${CYAN}# PetitPotam${NC}"
    echo "nxc smb ${TARGET_IP} -u 'guest' -p '' -M petitpotam"
    echo "nxc smb ${TARGET_IP} -u '' -p '' -M petitpotam"
    echo

    echo -e "${CYAN}# PrinterBug${NC}"
    echo "nxc smb ${TARGET_IP} -u 'guest' -p '' -M printerbug"
    echo "nxc smb ${TARGET_IP} -u '' -p '' -M printerbug"
    echo

    echo -e "${CYAN}# Coerce Plus${NC}"
    echo "nxc smb ${TARGET_IP} -u 'guest' -p '' -M coerce_plus"
    echo "nxc smb ${TARGET_IP} -u '' -p '' -M coerce_plus"
    echo

    echo -e "${CYAN}# Zerologon${NC}"
    echo "nxc smb ${TARGET_IP} -u 'guest' -p '' -M zerologon"
    echo "nxc smb ${TARGET_IP} -u '' -p '' -M zerologon"
    echo
}

print_summary() {
    section_header "SUMMARY"

    echo -e "${GREEN}Results saved to: ${OUT_DIR}/${NC}"
    echo
    echo -e "  Shares       → ${LOG_SHARES}"
    echo -e "  Users        → ${LOG_USERS}"
    echo -e "  Groups       → ${LOG_GROUPS}"
    echo -e "  Host Info    → ${LOG_RPC}"
    echo -e "  Pass Policy  → ${LOG_POLICY}"
    echo -e "  Vulns        → ${LOG_VULNS}"
    echo -e "  Nmap         → ${LOG_NMAP}"
    echo -e "  Enum4linux   → ${LOG_ENUM4LINUX}"
    [[ -s "${USERS_FILE}" ]] && echo -e "  User List    → ${USERS_FILE}"
    echo
    echo -e "${YELLOW}[!] No creds? Try usernames-as-passwords, cewl, or username-anarchy.${NC}"
    echo

    print_vuln_commands
}


# Main
main() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Unauthenticated SMB Enumeration Script             ║
║                   by strikoder                            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo "Target : ${TARGET_IP}"
    echo "Output : ${OUT_DIR}"
    echo

    enum_shares
    enum_users
    enum_groups
    enum_host_info
    enum_password_policy
    enum_enum4linux
    enum_vulnerabilities
    enum_nmap

    print_summary
}

main
