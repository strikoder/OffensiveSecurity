#!/bin/bash

# NetExec Credential Validation Script
# Checks credentials against multiple protocols with local and domain auth

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TARGET=""
PASSWORD=""
HASH=""
USER_INPUT=""
PROTOCOLS=()

# Banner
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  NetExec Credential Checker${NC}"
echo -e "${BLUE}================================${NC}\n"

# Check if nxc is installed
if ! command -v nxc &> /dev/null; then
    echo -e "${RED}[!] Error: NetExec (nxc) is not installed${NC}"
    echo -e "${YELLOW}[*] Install with: pip install netexec${NC}"
    exit 1
fi

# Function to display usage
usage() {
    echo "Usage: $0 -t <target> -u <username|userfile> [-p <password|passfile>] [-H <hash|hashfile>] [-a <auth_type>]"
    echo ""
    echo "Options:"
    echo "  -t <target>      Target IP or hostname (required)"
    echo "  -u <user>        Username or file with usernames (required)"
    echo "  -p <password>    Password or file with passwords"
    echo "  -H <hash>        NTLM hash or file with hashes"
    echo "  -a <auth_type>   Authentication type: both (default), local, domain"
    echo ""
    echo "Note: You must provide either -p (password) or -H (hash), but not both"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100 -u administrator -p 'Password123'"
    echo "  $0 -t 192.168.1.100 -u users.txt -p passwords.txt"
    echo "  $0 -t 192.168.1.100 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'"
    echo "  $0 -t 192.168.1.100 -u admin -p 'Password123' -a local"
    exit 1
}

# Parse command line arguments
AUTH_TYPE="both"
while getopts "t:p:u:H:a:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        u) USER_INPUT="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        H) HASH="$OPTARG" ;;
        a) AUTH_TYPE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [[ -z "$TARGET" || -z "$USER_INPUT" ]]; then
    echo -e "${RED}[!] Error: Target and username/userfile are required${NC}\n"
    usage
fi

# Check that either password or hash is provided, but not both
if [[ -z "$PASSWORD" && -z "$HASH" ]]; then
    echo -e "${RED}[!] Error: You must provide either -p (password) or -H (hash)${NC}\n"
    usage
fi

if [[ -n "$PASSWORD" && -n "$HASH" ]]; then
    echo -e "${RED}[!] Error: Cannot use both -p (password) and -H (hash) at the same time${NC}\n"
    usage
fi

# Validate auth type
if [[ "$AUTH_TYPE" != "both" && "$AUTH_TYPE" != "local" && "$AUTH_TYPE" != "domain" ]]; then
    echo -e "${RED}[!] Error: Invalid auth type. Use: both, local, or domain${NC}\n"
    usage
fi

# Create temporary file for results
RESULTS_FILE=$(mktemp)
trap "rm -f $RESULTS_FILE" EXIT

# Protocol selection menu
echo -e "${BLUE}[*] Select protocols to test (comma-separated numbers or 'all'):${NC}"
echo -e "  ${YELLOW}1${NC} - SMB"
echo -e "  ${YELLOW}2${NC} - WinRM"
echo -e "  ${YELLOW}3${NC} - RDP"
echo -e "  ${YELLOW}4${NC} - MSSQL"
echo -e "  ${YELLOW}5${NC} - FTP"
echo -e "  ${YELLOW}6${NC} - SSH"
echo -e "  ${YELLOW}7${NC} - LDAP"
echo -e "\nExample: 1,2,3 or all\n"
read -p "Selection: " protocol_choice

# Map selections to protocols
declare -A PROTOCOL_MAP
PROTOCOL_MAP[1]="smb"
PROTOCOL_MAP[2]="winrm"
PROTOCOL_MAP[3]="rdp"
PROTOCOL_MAP[4]="mssql"
PROTOCOL_MAP[5]="ftp"
PROTOCOL_MAP[6]="ssh"
PROTOCOL_MAP[7]="ldap"

if [[ "$protocol_choice" == "all" ]]; then
    PROTOCOLS=("smb" "winrm" "rdp" "mssql" "ftp" "ssh" "ldap")
else
    IFS=',' read -ra selections <<< "$protocol_choice"
    for selection in "${selections[@]}"; do
        selection=$(echo "$selection" | tr -d ' ')
        if [[ -n "${PROTOCOL_MAP[$selection]}" ]]; then
            PROTOCOLS+=("${PROTOCOL_MAP[$selection]}")
        else
            echo -e "${RED}[!] Warning: Invalid selection '$selection' ignored${NC}"
        fi
    done
fi

if [[ ${#PROTOCOLS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] Error: No valid protocols selected${NC}"
    exit 1
fi

# Function to test credentials
test_credentials() {
    local protocol=$1
    local target=$2
    local user_param=$3
    local cred_param=$4
    local cred_flag=$5
    local local_auth=$6
    
    local auth_type="Domain"
    local flag=""
    
    # FTP and SSH don't support --local-auth flag, so skip it for these protocols
    if [[ "$local_auth" == "true" && "$protocol" != "ftp" && "$protocol" != "ssh" ]]; then
        auth_type="Local"
        flag="--local-auth"
    elif [[ "$local_auth" == "true" && ( "$protocol" == "ftp" || "$protocol" == "ssh" ) ]]; then
        # For FTP/SSH with local auth mode, just note it but don't add the flag
        auth_type="Local/Domain (${protocol^^})"
    fi
    
    echo -e "\n${YELLOW}[*] Testing: ${protocol} | Auth: ${auth_type}${NC}"
    
    # Build and display the command
    local cmd="nxc $protocol $target -u $user_param $cred_flag $cred_param $flag --continue-on-success"
    echo -e "${BLUE}[CMD] $cmd${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Run nxc command with live output and color [+] lines green
    nxc "$protocol" "$target" -u "$user_param" $cred_flag "$cred_param" $flag --continue-on-success 2>&1 | \
    while IFS= read -r line; do
        if [[ "$line" == *"[+]"* ]]; then
            echo -e "${GREEN}${line}${NC}" | tee -a "$RESULTS_FILE"
        else
            echo "$line" | tee -a "$RESULTS_FILE"
        fi
    done
    
    local exit_code=${PIPESTATUS[0]}
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    return $exit_code
}

# Determine credential flag and parameter
if [[ -n "$HASH" ]]; then
    CRED_FLAG="-H"
    CRED_PARAM="$HASH"
    CRED_DISPLAY="Hash(es): $HASH"
else
    CRED_FLAG="-p"
    CRED_PARAM="$PASSWORD"
    CRED_DISPLAY="Password(s): $PASSWORD"
fi

# Main execution
echo -e "\n${BLUE}[*] Target: $TARGET${NC}"
echo -e "${BLUE}[*] User(s): $USER_INPUT${NC}"
echo -e "${BLUE}[*] $CRED_DISPLAY${NC}"

# Display authentication mode
if [[ "$AUTH_TYPE" == "both" ]]; then
    echo -e "${GREEN}[*] Auth Mode: BOTH (Domain + Local)${NC}"
elif [[ "$AUTH_TYPE" == "local" ]]; then
    echo -e "${GREEN}[*] Auth Mode: LOCAL ONLY${NC}"
else
    echo -e "${GREEN}[*] Auth Mode: DOMAIN ONLY${NC}"
fi

echo -e "${BLUE}[*] Protocols: ${PROTOCOLS[*]}${NC}"
echo -e "${BLUE}[*] Starting credential validation...${NC}\n"

# Test each protocol
for protocol in "${PROTOCOLS[@]}"; do
    echo -e "\n${BLUE}========== Testing protocol: $protocol ==========${NC}"
    
    # Check if protocol supports hash authentication
    if [[ -n "$HASH" && ( "$protocol" == "ftp" || "$protocol" == "ssh" ) ]]; then
        echo -e "${YELLOW}[!] Warning: ${protocol^^} does not support hash authentication - skipping${NC}"
        continue
    fi
    
    # Determine which auth types to test
    if [[ "$AUTH_TYPE" == "both" ]]; then
        # Test domain auth
        test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$CRED_PARAM" "$CRED_FLAG" "false"
        sleep 1
        
        # Test local auth (skip for FTP and SSH as they don't support --local-auth)
        if [[ "$protocol" != "ftp" && "$protocol" != "ssh" ]]; then
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$CRED_PARAM" "$CRED_FLAG" "true"
            sleep 1
        else
            echo -e "${YELLOW}[*] Note: ${protocol^^} protocol tested without --local-auth flag (not supported)${NC}"
        fi
    elif [[ "$AUTH_TYPE" == "local" ]]; then
        # Test local auth only (or domain for FTP/SSH)
        test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$CRED_PARAM" "$CRED_FLAG" "true"
        sleep 1
    else
        # Test domain auth only
        test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$CRED_PARAM" "$CRED_FLAG" "false"
        sleep 1
    fi
done

# Display results summary
echo -e "\n${BLUE}================================${NC}"
echo -e "${BLUE}     Results Summary${NC}"
echo -e "${BLUE}================================${NC}\n"

if [[ -s "$RESULTS_FILE" ]]; then
    # Extract and display valid credentials
    grep -E '\(\+\)|Pwn3d!|SUCCESS' "$RESULTS_FILE" 2>/dev/null || echo -e "${YELLOW}[*] Check output above for results${NC}"
    echo -e "\n${GREEN}[+] Testing completed!${NC}"
    echo -e "${YELLOW}[*] Full results saved to: $RESULTS_FILE${NC}"
    echo -e "${YELLOW}[*] Copy results before script exits to preserve them${NC}"
else
    echo -e "${YELLOW}[*] Testing completed - check output above for results${NC}"
fi

echo ""
