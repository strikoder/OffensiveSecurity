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
    echo "Usage: $0 -t <target> -u <username|userfile> [-p <password|passfile>] [-H <hash|hashfile>] [-a <auth_type>] [--spray|--no-spray]"
    echo ""
    echo "Options:"
    echo "  -t <target>      Target IP or hostname (required)"
    echo "  -u <user>        Username or file with usernames (required)"
    echo "  -p <password>    Password or file with passwords"
    echo "  -H <hash>        NTLM hash or file with hashes"
    echo "  -a <auth_type>   Authentication type: both (default), local, domain"
    echo "  --spray          Spray mode: test all users with all passwords (DEFAULT)"
    echo "  --no-spray       No-spray mode: pair credentials (user1:pass1, user2:pass2)"
    echo ""
    echo "Note: You must provide either -p (password) or -H (hash), but not both"
    echo "      Exception: --no-spray mode with mixed credentials auto-detects"
    echo ""
    echo "File Formats:"
    echo "  - Simple list: one username/password/hash per line"
    echo "  - Combined format: user:pass or user:hash (one per line)"
    echo "  - Mixed format (--no-spray): auto-detects passwords vs hashes"
    echo "  - Lines with only username (no credential) are skipped in --no-spray mode"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100 -u administrator -p 'Password123'"
    echo "  $0 -t 192.168.1.100 -u users.txt -p passwords.txt --spray"
    echo "  $0 -t 192.168.1.100 -u users.txt -p users.txt --no-spray"
    echo "  $0 -t 192.168.1.100 -u creds.txt -p creds.txt --no-spray   # Auto-detects pass/hash"
    echo "  $0 -t 192.168.1.100 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'"
    exit 1
}

# Function to detect if a string is an NTLM hash
is_hash() {
    local cred=$1
    # NTLM hash patterns:
    # - 32 hex chars (LM or NTLM hash)
    # - 65 hex chars with colon (LM:NTLM format)
    if [[ "$cred" =~ ^[a-fA-F0-9]{32}$ ]] || [[ "$cred" =~ ^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$ ]]; then
        return 0
    fi
    return 1
}

# Check for --help or --version before getopts
SPRAY_MODE=true
for arg in "$@"; do
    if [[ "$arg" == "--help" || "$arg" == "-help" ]]; then
        usage
    elif [[ "$arg" == "--no-spray" ]]; then
        SPRAY_MODE=false
    elif [[ "$arg" == "--spray" ]]; then
        SPRAY_MODE=true
    fi
done

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

# Check that either password or hash is provided
if [[ -z "$PASSWORD" && -z "$HASH" ]]; then
    echo -e "${RED}[!] Error: You must provide either -p (password) or -H (hash)${NC}\n"
    usage
fi

# Allow both -p and -H only in no-spray mode (for auto-detection)
if [[ -n "$PASSWORD" && -n "$HASH" && "$SPRAY_MODE" == true ]]; then
    echo -e "${RED}[!] Error: Cannot use both -p (password) and -H (hash) in spray mode${NC}\n"
    usage
fi

# Validate auth type
if [[ "$AUTH_TYPE" != "both" && "$AUTH_TYPE" != "local" && "$AUTH_TYPE" != "domain" ]]; then
    echo -e "${RED}[!] Error: Invalid auth type. Use: both, local, or domain${NC}\n"
    usage
fi

# Create temporary file for results
RESULTS_FILE=$(mktemp)
SKIP_CURRENT=false

# Trap function to handle Ctrl+C
handle_interrupt() {
    echo -e "\n${YELLOW}[!] Ctrl+C detected - Skipping current test...${NC}"
    SKIP_CURRENT=true
    # Kill the current nxc process if running
    pkill -P $ nxc 2>/dev/null || true
}

trap handle_interrupt SIGINT
trap "rm -f $RESULTS_FILE" EXIT

# Function to parse credential file with auto-detection (--no-spray mode)
parse_credential_file_smart() {
    local file=$1
    local temp_users=$(mktemp)
    local temp_passes=$(mktemp)
    local temp_hashes=$(mktemp)
    local skipped=0
    local pass_count=0
    local hash_count=0
    
    echo -e "${YELLOW}[*] Processing credential file with auto-detection (no-spray mode)...${NC}" >&2
    
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Trim whitespace
        line=$(echo "$line" | xargs)
        
        # Check if line contains colon
        if [[ "$line" == *:* ]]; then
            local user=$(echo "$line" | cut -d':' -f1 | xargs)
            local cred=$(echo "$line" | cut -d':' -f2- | xargs)
            
            # Skip if line starts with : (no username)
            if [[ -z "$user" ]]; then
                ((skipped++))
                echo -e "${YELLOW}[*] Skipping line with no username: :$cred${NC}" >&2
                continue
            fi
            
            # Skip if no credential after colon (user: with nothing after)
            if [[ -z "$cred" ]]; then
                ((skipped++))
                echo -e "${YELLOW}[*] Skipping line with no credential: $user:${NC}" >&2
                continue
            fi
            
            # Detect if credential is hash or password
            if is_hash "$cred"; then
                echo "$user" >> "$temp_users"
                echo "$cred" >> "$temp_hashes"
                ((hash_count++))
            else
                echo "$user" >> "$temp_users"
                echo "$cred" >> "$temp_passes"
                ((pass_count++))
            fi
        else
            # Line with only username (no colon, no credential)
            # In --no-spray mode, skip users without credentials
            ((skipped++))
            echo -e "${YELLOW}[*] Skipping username without credential: $line${NC}" >&2
        fi
    done < "$file"
    
    if [[ $skipped -gt 0 ]]; then
        echo -e "${YELLOW}[*] Skipped $skipped line(s) with missing or incomplete credentials${NC}" >&2
    fi
    
    echo -e "${GREEN}[*] Detected: $pass_count password(s), $hash_count hash(es)${NC}" >&2
    
    echo "$temp_users:$temp_passes:$temp_hashes:$pass_count:$hash_count"
}

# Function to parse credential file for spray mode (extracts all users and all creds separately)
parse_credential_file_spray() {
    local file=$1
    local temp_users=$(mktemp)
    local temp_passes=$(mktemp)
    local temp_hashes=$(mktemp)
    local pass_count=0
    local hash_count=0
    local user_count=0
    
    echo -e "${YELLOW}[*] Processing credential file for spray mode...${NC}" >&2
    
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Trim whitespace
        line=$(echo "$line" | xargs)
        
        # Check if line contains colon
        if [[ "$line" == *:* ]]; then
            local user=$(echo "$line" | cut -d':' -f1 | xargs)
            local cred=$(echo "$line" | cut -d':' -f2- | xargs)
            
            # Add user if present
            if [[ -n "$user" ]]; then
                echo "$user" >> "$temp_users"
                ((user_count++))
            fi
            
            # Add credential if present and detect type
            if [[ -n "$cred" ]]; then
                if is_hash "$cred"; then
                    echo "$cred" >> "$temp_hashes"
                    ((hash_count++))
                else
                    echo "$cred" >> "$temp_passes"
                    ((pass_count++))
                fi
            fi
        else
            # Line with only username (no colon) - add to users list
            echo "$line" >> "$temp_users"
            ((user_count++))
        fi
    done < "$file"
    
    echo -e "${GREEN}[*] Spray mode: Extracted $user_count user(s), $pass_count password(s), $hash_count hash(es)${NC}" >&2
    
    echo "$temp_users:$temp_passes:$temp_hashes:$pass_count:$hash_count"
}

# Function to parse simple credential file (spray mode or same type)
parse_credential_file_simple() {
    local file=$1
    local temp_users=$(mktemp)
    local temp_creds=$(mktemp)
    local is_combined=false
    local skipped=0
    
    # Check if file contains colon-separated format
    if grep -q ':' "$file"; then
        is_combined=true
        echo -e "${YELLOW}[*] Detected combined format (user:credential) in file${NC}" >&2
        
        while IFS=: read -r user cred; do
            # Skip empty lines
            [[ -z "$user" && -z "$cred" ]] && continue
            
            # Trim whitespace
            user=$(echo "$user" | xargs)
            cred=$(echo "$cred" | xargs)
            
            if [[ -z "$user" || -z "$cred" ]]; then
                ((skipped++))
                continue
            fi
            
            echo "$user" >> "$temp_users"
            echo "$cred" >> "$temp_creds"
        done < "$file"
        
        if [[ $skipped -gt 0 ]]; then
            echo -e "${YELLOW}[*] Skipped $skipped line(s) with missing user or credential${NC}" >&2
        fi
    else
        # Simple list format - just copy the file
        cp "$file" "$temp_users"
        cp "$file" "$temp_creds"
    fi
    
    echo "$temp_users:$temp_creds:$is_combined"
}

# Process input files
TEMP_USER_FILE=""
TEMP_PASS_FILE=""
TEMP_HASH_FILE=""
USE_TEMP_FILES=false
HAS_PASSWORDS=false
HAS_HASHES=false

if [[ "$SPRAY_MODE" == false ]]; then
    # No-spray mode: handle paired credentials with auto-detection
    if [[ -f "$USER_INPUT" ]]; then
        if [[ -n "$PASSWORD" && -f "$PASSWORD" ]]; then
            if [[ "$USER_INPUT" == "$PASSWORD" ]]; then
                echo -e "${BLUE}[*] No-spray mode: Processing combined credential file...${NC}"
                
                # Smart parsing with auto-detection (skips users without creds)
                result=$(parse_credential_file_smart "$USER_INPUT")
                TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
                TEMP_PASS_FILE=$(echo "$result" | cut -d: -f2)
                TEMP_HASH_FILE=$(echo "$result" | cut -d: -f3)
                pass_count=$(echo "$result" | cut -d: -f4)
                hash_count=$(echo "$result" | cut -d: -f5)
                
                USE_TEMP_FILES=true
                
                # Set flags based on what we found
                if [[ $pass_count -gt 0 ]]; then
                    HAS_PASSWORDS=true
                    PASSWORD="$TEMP_PASS_FILE"
                fi
                if [[ $hash_count -gt 0 ]]; then
                    HAS_HASHES=true
                    HASH="$TEMP_HASH_FILE"
                fi
                
                # Update USER_INPUT for both
                USER_INPUT="$TEMP_USER_FILE"
            else
                # Different files - use simple parsing
                result=$(parse_credential_file_simple "$PASSWORD")
                TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
                TEMP_PASS_FILE=$(echo "$result" | cut -d: -f2)
                USE_TEMP_FILES=true
                USER_INPUT="$TEMP_USER_FILE"
                PASSWORD="$TEMP_PASS_FILE"
                HAS_PASSWORDS=true
            fi
        elif [[ -n "$HASH" && -f "$HASH" ]]; then
            if [[ "$USER_INPUT" == "$HASH" ]]; then
                echo -e "${BLUE}[*] No-spray mode: Processing combined hash file...${NC}"
                result=$(parse_credential_file_simple "$USER_INPUT")
                TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
                TEMP_HASH_FILE=$(echo "$result" | cut -d: -f2)
                USE_TEMP_FILES=true
                USER_INPUT="$TEMP_USER_FILE"
                HASH="$TEMP_HASH_FILE"
                HAS_HASHES=true
            else
                echo -e "${RED}[!] Error: --no-spray mode requires the same file for -u and -H${NC}"
                exit 1
            fi
        else
            echo -e "${RED}[!] Error: --no-spray mode requires both user and credential files${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[!] Error: --no-spray mode requires file input, not single values${NC}"
        exit 1
    fi
else
    # Spray mode: extract all users and all credentials separately
    echo -e "${GREEN}[*] Spray mode: Testing all users with all passwords/hashes${NC}"
    
    # Check if we're using the same file for users and credentials
    if [[ -f "$USER_INPUT" && -n "$PASSWORD" && "$USER_INPUT" == "$PASSWORD" ]]; then
        echo -e "${BLUE}[*] Spray mode: Extracting users and credentials from same file...${NC}"
        
        # Parse file to extract users and credentials separately
        result=$(parse_credential_file_spray "$USER_INPUT")
        TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
        TEMP_PASS_FILE=$(echo "$result" | cut -d: -f2)
        TEMP_HASH_FILE=$(echo "$result" | cut -d: -f3)
        pass_count=$(echo "$result" | cut -d: -f4)
        hash_count=$(echo "$result" | cut -d: -f5)
        
        USE_TEMP_FILES=true
        USER_INPUT="$TEMP_USER_FILE"
        
        if [[ $pass_count -gt 0 ]]; then
            HAS_PASSWORDS=true
            PASSWORD="$TEMP_PASS_FILE"
        fi
        if [[ $hash_count -gt 0 ]]; then
            HAS_HASHES=true
            HASH="$TEMP_HASH_FILE"
        fi
    elif [[ -f "$USER_INPUT" && -n "$HASH" && "$USER_INPUT" == "$HASH" ]]; then
        echo -e "${BLUE}[*] Spray mode: Extracting users and hashes from same file...${NC}"
        
        # Parse file to extract users and credentials separately
        result=$(parse_credential_file_spray "$USER_INPUT")
        TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
        TEMP_PASS_FILE=$(echo "$result" | cut -d: -f2)
        TEMP_HASH_FILE=$(echo "$result" | cut -d: -f3)
        pass_count=$(echo "$result" | cut -d: -f4)
        hash_count=$(echo "$result" | cut -d: -f5)
        
        USE_TEMP_FILES=true
        USER_INPUT="$TEMP_USER_FILE"
        
        if [[ $pass_count -gt 0 ]]; then
            HAS_PASSWORDS=true
            PASSWORD="$TEMP_PASS_FILE"
        fi
        if [[ $hash_count -gt 0 ]]; then
            HAS_HASHES=true
            HASH="$TEMP_HASH_FILE"
        fi
    else
        # Different files or single values - use as-is
        if [[ -n "$PASSWORD" ]]; then
            HAS_PASSWORDS=true
        fi
        if [[ -n "$HASH" ]]; then
            HAS_HASHES=true
        fi
    fi
fi

# Cleanup function for temp files
cleanup_temp_files() {
    if [[ "$USE_TEMP_FILES" == true ]]; then
        [[ -n "$TEMP_USER_FILE" && -f "$TEMP_USER_FILE" ]] && rm -f "$TEMP_USER_FILE"
        [[ -n "$TEMP_PASS_FILE" && -f "$TEMP_PASS_FILE" ]] && rm -f "$TEMP_PASS_FILE"
        [[ -n "$TEMP_HASH_FILE" && -f "$TEMP_HASH_FILE" ]] && rm -f "$TEMP_HASH_FILE"
    fi
}
trap cleanup_temp_files EXIT

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
    
    # Reset skip flag at the start of each test
    SKIP_CURRENT=false
    
    local auth_type="Domain"
    local flag=""
    
    # FTP and SSH don't support --local-auth flag
    if [[ "$local_auth" == "true" && "$protocol" != "ftp" && "$protocol" != "ssh" ]]; then
        auth_type="Local"
        flag="--local-auth"
    elif [[ "$local_auth" == "true" && ( "$protocol" == "ftp" || "$protocol" == "ssh" ) ]]; then
        auth_type="Local/Domain (${protocol^^})"
    fi
    
    echo -e "\n${YELLOW}[*] Testing: ${protocol} | Auth: ${auth_type}${NC}"
    
    # Build and display the command
    local cmd="nxc $protocol $target -u $user_param $cred_flag $cred_param $flag --continue-on-success"
    echo -e "${BLUE}[CMD] $cmd${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Create temporary file for output
    local output_file=$(mktemp)
    
    # Run nxc command with live output and color [+] lines green
    nxc "$protocol" "$target" -u "$user_param" $cred_flag "$cred_param" $flag --continue-on-success 2>&1 | \
    tee "$output_file" | \
    while IFS= read -r line; do
        # Check if we should skip
        if [[ "$SKIP_CURRENT" == true ]]; then
            break
        fi
        
        if [[ "$line" == *"[+]"* ]]; then
            # Print with green color and explicit color reset
            printf "${GREEN}%s${NC}\n" "$line" | tee -a "$RESULTS_FILE"
        else
            # Print normally
            printf "%s\n" "$line" | tee -a "$RESULTS_FILE"
        fi
    done
    
    local exit_code=${PIPESTATUS[0]}
    
    # If skipped, clean up and return early
    if [[ "$SKIP_CURRENT" == true ]]; then
        rm -f "$output_file"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}[*] Test skipped by user${NC}\n"
        return 0
    fi
    
    # Check for status_not_supported error
    if grep -qi "status_not_supported" "$output_file"; then
        rm -f "$output_file"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        echo -e "${RED}[!] ERROR DETECTED: status_not_supported${NC}\n"
        
        echo -e "${YELLOW}[!] This error typically indicates a Kerberos authentication problem.${NC}\n"
        
        echo -e "${BLUE}SOLUTION 1: Use Manual Kerberos Enumeration${NC}"
        echo -e "${GREEN}Add the '-k' flag to manually specify Kerberos authentication:${NC}\n"
        echo -e "  ${YELLOW}nxc smb HOST_NAME -u $USER_INPUT -p '$PASSWORD' -k${NC}\n"
        
        echo -e "${BLUE}SOLUTION 2: Fix Time Synchronization (if you see KRB_AP_ERR_SKEW)${NC}"
        echo -e "${GREEN}Kerberos requires time sync within 5 minutes. Run these commands:${NC}\n"
        echo -e "  ${YELLOW}sudo systemctl restart systemd-timesyncd.service${NC}  ${BLUE}# If using systemd-timesyncd${NC}"
        echo -e "  ${YELLOW}sudo timedatectl set-ntp no${NC}                      ${BLUE}# Disable automatic NTP${NC}"
        echo -e "  ${YELLOW}sudo ntpdate -u $TARGET${NC}                          ${BLUE}# Sync with target${NC}\n"
        
        echo -e "${BLUE}Note:${NC} The first 2 commands depend on your VM configuration."
        echo -e "      You might not need them if you're not using systemd-timesyncd.\n"
        
        echo -e "${RED}[!] Script stopped to prevent further errors.${NC}\n"
        exit 1
    fi
    
    rm -f "$output_file"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    return $exit_code
}

# Main execution
echo -e "\n${BLUE}[*] Target: $TARGET${NC}"
echo -e "${BLUE}[*] User(s): $USER_INPUT${NC}"

if [[ "$HAS_PASSWORDS" == true ]]; then
    echo -e "${BLUE}[*] Password(s): $PASSWORD${NC}"
fi
if [[ "$HAS_HASHES" == true ]]; then
    echo -e "${BLUE}[*] Hash(es): $HASH${NC}"
fi

# Display authentication mode
if [[ "$AUTH_TYPE" == "both" ]]; then
    echo -e "${GREEN}[*] Auth Mode: BOTH (Domain + Local)${NC}"
elif [[ "$AUTH_TYPE" == "local" ]]; then
    echo -e "${GREEN}[*] Auth Mode: LOCAL ONLY${NC}"
else
    echo -e "${GREEN}[*] Auth Mode: DOMAIN ONLY${NC}"
fi

# Display spray mode
if [[ "$SPRAY_MODE" == true ]]; then
    echo -e "${GREEN}[*] Credential Mode: SPRAY (all users x all passwords)${NC}"
else
    echo -e "${YELLOW}[*] Credential Mode: NO-SPRAY (paired credentials only)${NC}"
fi

echo -e "${BLUE}[*] Protocols: ${PROTOCOLS[*]}${NC}"
echo -e "${BLUE}[*] Starting credential validation...${NC}"
echo -e "${YELLOW}[*] Press Ctrl+C once to skip current test and move to next${NC}\n"

# Test each protocol
for protocol in "${PROTOCOLS[@]}"; do
    # Check if we should skip due to interrupt
    if [[ "$SKIP_CURRENT" == true ]]; then
        echo -e "${YELLOW}[*] Skipping remaining protocols...${NC}"
        break
    fi
    
    echo -e "\n${BLUE}========== Testing protocol: $protocol ==========${NC}"
    
    # Test with passwords if we have them
    if [[ "$HAS_PASSWORDS" == true ]]; then
        # Check if we should skip
        if [[ "$SKIP_CURRENT" == true ]]; then
            echo -e "${YELLOW}[*] Skipping password tests for $protocol...${NC}"
        else
            # Determine which auth types to test
            if [[ "$AUTH_TYPE" == "both" ]]; then
                # Test domain auth
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "false"
                sleep 1
                
                # Test local auth (skip for FTP and SSH)
                if [[ "$SKIP_CURRENT" == false ]]; then
                    if [[ "$protocol" != "ftp" && "$protocol" != "ssh" ]]; then
                        test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "true"
                        sleep 1
                    else
                        echo -e "${YELLOW}[*] Note: ${protocol^^} protocol tested without --local-auth flag (not supported)${NC}"
                    fi
                fi
            elif [[ "$AUTH_TYPE" == "local" ]]; then
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "true"
                sleep 1
            else
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "false"
                sleep 1
            fi
        fi
        # Reset skip flag for next credential type
        SKIP_CURRENT=false
    fi
    
    # Test with hashes if we have them
    if [[ "$HAS_HASHES" == true ]]; then
        # Check if protocol supports hash authentication
        if [[ "$protocol" == "ftp" || "$protocol" == "ssh" ]]; then
            echo -e "${YELLOW}[!] Warning: ${protocol^^} does not support hash authentication - skipping${NC}"
            continue
        fi
        
        # Check if we should skip
        if [[ "$SKIP_CURRENT" == true ]]; then
            echo -e "${YELLOW}[*] Skipping hash tests for $protocol...${NC}"
        else
            # Determine which auth types to test
            if [[ "$AUTH_TYPE" == "both" ]]; then
                # Test domain auth
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "false"
                sleep 1
                
                # Test local auth
                if [[ "$SKIP_CURRENT" == false ]]; then
                    test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "true"
                    sleep 1
                fi
            elif [[ "$AUTH_TYPE" == "local" ]]; then
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "true"
                sleep 1
            else
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "false"
                sleep 1
            fi
        fi
        # Reset skip flag for next protocol
        SKIP_CURRENT=false
    fi
done

# Display results summary
echo -e "\n${BLUE}================================${NC}"
echo -e "${BLUE}     Results Summary${NC}"
echo -e "${BLUE}================================${NC}\n"

if [[ -s "$RESULTS_FILE" ]]; then
    # Extract and display valid credentials
    grep -E '\[\+\]' "$RESULTS_FILE" 2>/dev/null || echo -e "${YELLOW}[*] Check output above for results${NC}"
    echo -e "\n${GREEN}[+] Testing completed!${NC}"
    echo -e "${YELLOW}[*] Full results saved to: $RESULTS_FILE${NC}"
    echo -e "${YELLOW}[*] Copy results before script exits to preserve them${NC}"
else
    echo -e "${YELLOW}[*] Testing completed - check output above for results${NC}"
fi

echo ""
