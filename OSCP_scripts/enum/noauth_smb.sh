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

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Validate arguments
if [[ $# -ne 1 ]]; then
    echo -e "${RED}[!] Usage: ${SCRIPT_NAME} <IP>${NC}" >&2
    exit 1
fi

readonly TARGET_IP="$1"
readonly OUT_DIR="results_noauth_smb/${TARGET_IP}_${TIMESTAMP}"
readonly DOWNLOAD_DIR="${OUT_DIR}/downloads"

# Create output directories
mkdir -p "${OUT_DIR}" "${DOWNLOAD_DIR}"

# Output files
readonly SMBCLIENT_LOG="${OUT_DIR}/smbclient_shares.log"
readonly NXC_RID_LOG="${OUT_DIR}/nxc_rid_brute.log"
readonly NXC_USERS_LOG="${OUT_DIR}/nxc_users.log"
readonly USERS_FILE="${OUT_DIR}/users.txt"
readonly RPC_LOG="${OUT_DIR}/rpcclient.log"
readonly NXC_PASSPOL_LOG="${OUT_DIR}/nxc_passpol.log"
readonly NXC_MODULES_LOG="${OUT_DIR}/nxc_modules.log"

log_warning() {
    echo -e "${YELLOW}[!] $*${NC}"
}

log_error() {
    echo -e "${RED}[-] $*${NC}" >&2
}

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


# Main enumeration functions
enum_nmap() {
    section_header "NMAP SMB SCRIPTS"
    nmap -Pn -p445 -sV \
        --script "smb-security-mode,smb-protocols,smb2-capabilities,smb-vuln-ms17-010" \
        "${TARGET_IP}" 2>&1 || log_warning "Nmap scan failed"
}

enum_smbclient_shares() {
    section_header "SMBCLIENT - NULL SESSION"
    smbclient -N -L "\\\\${TARGET_IP}\\" 2>&1 | tee "${SMBCLIENT_LOG}" || log_warning "Null session access denied or failed"
}

enum_nxc_rid_brute() {
    section_header "NETEXEC - RID BRUTE FORCE"
    nxc smb "${TARGET_IP}" -u "guest" -p "" --rid-brute 2>&1 | tee "${NXC_RID_LOG}" || log_warning "RID brute enumeration failed"
    nxc smb "${TARGET_IP}" -u "" -p "" --rid-brute 2>&1 | tee "${NXC_RID_LOG}" || log_warning "RID brute enumeration failed"
}

enum_nxc_users() {
    section_header "NETEXEC - USER ENUMERATION"
    nxc smb "${TARGET_IP}" -u "guest" -p "" --users 2>&1 | tee "${NXC_USERS_LOG}" || log_warning "User enumeration failed"
    nxc smb "${TARGET_IP}" -u "" -p "" --users 2>&1 | tee "${NXC_USERS_LOG}" || log_warning "User enumeration failed"

    # Extract usernames to users.txt
    if [[ -f "${NXC_USERS_LOG}" ]]; then
        awk '{print $5}' "${NXC_USERS_LOG}" | sed '1,3d;$d' | sort -u > "${USERS_FILE}" 2>/dev/null || true
        if [[ -s "${USERS_FILE}" ]]; then
            local user_count=$(wc -l < "${USERS_FILE}")
            echo "Extracted ${user_count} username(s) to: ${USERS_FILE}"
        fi
    fi

}

enum_rpcclient() {
    section_header "RPCCLIEN T- MSRPC ENUMERATION"
    {
        echo "srvinfo"
        echo "lsaquery"
        echo "enumdomains"
        echo "querydominfo"
        echo "enumdomusers"
        echo "enumdomgroups"
        echo "querydispinfo"
    } | rpcclient -U "" -N "${TARGET_IP}" 2>&1 | tee "${RPC_LOG}" || log_warning "rpcclient failed"
}

enum_nxc_modules() {
    section_header "NETEXEC - VULNERABILITY MODULES"
    local modules=(gpp_password gpp_autologin smbghost printnightmare coerce_plus nopac)
    
    for module in "${modules[@]}"; do
        echo -e "\n${YELLOW}[>] Module: ${module}${NC}"
        {
            nxc smb "${TARGET_IP}" -u 'guest' -p '' -M "${module}" 2>&1
            nxc smb "${TARGET_IP}" -u '' -p '' -M "${module}" 2>&1
        } | tee -a "${NXC_MODULES_LOG}" || true
    done
}

enum_password_policy() {
    section_header "PASSWORD POLICY"
    {
        nxc smb "${TARGET_IP}" -u 'guest' -p '' --pass-pol 2>&1
        nxc smb "${TARGET_IP}" -u '' -p '' --pass-pol 2>&1
    } | tee "${NXC_PASSPOL_LOG}" || log_warning "Password policy enumeration failed"
}

enum_enum4linux() {
    section_header "ENUM4LINUX-NG"
    enum4linux-ng -A "${TARGET_IP}" 2>&1 || log_warning "enum4linux-ng failed"
}

enum_smbmap() {
    section_header "SMBMAP - SHARE PERMISSIONS"
    smbmap -H "${TARGET_IP}" -u 'guest' 2>&1 || log_warning "smbmap with null session failed"
    echo
    smbmap -H "${TARGET_IP}" -u '' -p '' 2>&1 || log_warning "smbmap with  failed"
}


print_summary() {
    section_header "ENUMERATION SUMMARY"
    
    echo
    echo "Results saved to: ${OUT_DIR}/"
    echo
    echo -e "${YELLOW}[!] ZEROLOGON (CVE-2020-1472) - Run manually if needed:${NC}"
    echo -e "    ${CYAN}nxc smb ${TARGET_IP} -u '' -p '' -M zerologon${NC}"
    echo
    echo -e "${YELLOW}[!] If you don't have credentials, consider using usernames as passwords or using cewl or username-anarchy${NC}"
    echo 
}

# Main execution
main() {
    clear
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
    
    echo "Target: ${TARGET_IP}"
    echo "Output Directory: ${OUT_DIR}"
    echo
    
    # Run enumeration
    enum_smbclient_shares
    enum_nxc_rid_brute
    enum_nxc_users
    enum_rpcclient
    enum_nxc_modules
    enum_password_policy
    enum_enum4linux
    enum_smbmap
    enum_nmap
    # Summary
    print_summary
}
# Run main function
main
