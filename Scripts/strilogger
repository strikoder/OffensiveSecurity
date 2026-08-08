#!/bin/bash

# strilogger - Comprehensive tmux logging script with real-time capture
# Usage:
#   ./strilogger [IP]     - Start logging (optionally with IP in filename)
#   ./strilogger stop     - Stop all logging

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.strilogger.pid"
CURRENT_LOG="$SCRIPT_DIR/.strilogger.current"
CURRENT_IP="$SCRIPT_DIR/.strilogger.ip"
LOG_DIR="$HOME/Desktop/logs"
IP_MAP="$SCRIPT_DIR/.strilogger.ipmap"
SHELL_HOOK_FILE="$HOME/.strilogger_hooks.sh"

# Detect shell RC file
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    RC_FILE="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
    RC_FILE="$HOME/.bashrc"
else
    RC_FILE="$HOME/.bashrc"
fi

# Color codes for output
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Function to generate log filename
generate_logfile() {
    local ip="$1"
    local timestamp
    timestamp=$(date -u '+%Y%m%d_%H%M%S')
    if [ -n "$ip" ]; then
        echo "$LOG_DIR/strilog_${ip}_${timestamp}.log"
    else
        echo "$LOG_DIR/strilog_${timestamp}.log"
    fi
}

# Function to get existing logfile for IP
get_logfile_for_ip() {
    local ip="$1"
    if [ -f "$IP_MAP" ]; then
        grep "^${ip}:" "$IP_MAP" | cut -d: -f2
    fi
}

# Function to save IP mapping
save_ip_mapping() {
    local ip="$1"
    local logfile="$2"
    # Remove old mapping for this IP
    if [ -f "$IP_MAP" ]; then
        grep -v "^${ip}:" "$IP_MAP" > "$IP_MAP.tmp" 2>/dev/null || true
        mv "$IP_MAP.tmp" "$IP_MAP"
    fi
    # Add new mapping
    echo "${ip}:${logfile}" >> "$IP_MAP"
}

# Function to stop logging
stop_logging() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid" 2>/dev/null
            echo -e "${GREEN}[+] Stopped logging (PID: $pid)${RESET}"
        else
            echo -e "${YELLOW}[!] No active logging process found${RESET}"
        fi
        rm -f "$PID_FILE"
        rm -f "$CURRENT_LOG"
        rm -f "$CURRENT_IP"
    else
        echo -e "${YELLOW}[!] No active logging session${RESET}"
    fi
    
    # Clean up tmux hooks and configuration
    if [ -n "$TMUX" ]; then
        tmux set-option -gu status-right 2>/dev/null
        tmux set-option -g status-interval 15 2>/dev/null
        tmux set-hook -gu window-linked 2>/dev/null
        tmux set-hook -gu window-unlinked 2>/dev/null
    fi
    
    # Remove strilogger block from RC file
    if [ -f "$RC_FILE" ]; then
        sed -i '/### STRILOGGER START ###/,/### STRILOGGER END ###/d' "$RC_FILE"
        echo -e "${CYAN}[+] Removed hooks from $RC_FILE${RESET}"
    fi
    
    # Remove shell hooks file
    rm -f "$SHELL_HOOK_FILE"
    
    echo -e "${CYAN}[+] Logging fully stopped. Open new terminals/panes for changes to take effect.${RESET}"
}

# Function to get UTC timestamp
get_utc_timestamp() {
    date -u +'%Y-%m-%d %H:%M:%S UTC'
}

# Function to add hooks to RC file
add_hooks_to_rc() {
    local logfile="$1"
    
    # Remove old hooks if they exist
    if grep -q "### STRILOGGER START ###" "$RC_FILE"; then
        sed -i '/### STRILOGGER START ###/,/### STRILOGGER END ###/d' "$RC_FILE"
    fi
    
    # Add new hooks
    cat >> "$RC_FILE" <<'EOFRC'

### STRILOGGER START ###
export STRILOGGER_ACTIVE=1
export STRILOGGER_LOG="LOGFILE_PLACEHOLDER"

strilogger_log_command() {
    [[ -z "$STRILOGGER_ACTIVE" ]] && return
    [[ -z "$STRILOGGER_LOG" ]] && return
    
    local cmd="$1"
    local timestamp=$(date -u +'%Y-%m-%d %H:%M:%S UTC')
    local tun0=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
    
    {
        echo ""
        if [[ -n "$tun0" ]]; then
            printf "┌──(%s@%s)-[%s] [%s] [tun0:%s]\n" \
                "$USER" "$(hostname)" "${PWD/#$HOME/~}" "$timestamp" "$tun0"
        else
            printf "┌──(%s@%s)-[%s] [%s]\n" \
                "$USER" "$(hostname)" "${PWD/#$HOME/~}" "$timestamp"
        fi
        printf "└─$ %s\n" "$cmd"
    } >> "$STRILOGGER_LOG"
}

# Helper for prompt time
strilogger_prompt_time() {
    date -u +'%Y-%m-%d %H:%M:%S UTC'
}


# Zsh hooks
if [ -n "$ZSH_VERSION" ]; then
    autoload -Uz add-zsh-hook
    strilogger_preexec_zsh() {
        strilogger_log_command "$1"
    }
    add-zsh-hook preexec strilogger_preexec_zsh
    setopt promptsubst
    
    # Fixed Prompt for Zsh with Kali Colors
    if [[ "$PROMPT" != *'strilogger_prompt_time'* ]]; then
        if [ "$EUID" -eq 0 ]; then
            USER_COLOR='%F{red}' # Red for root
        else
            USER_COLOR='%F{green}' # Green for user
        fi
	PROMPT='┌──('"$USER_COLOR"'%n㉿%m)-[%F{reset}%~%F{blue}] %F{yellow}$(strilogger_prompt_time)%f
%F{blue}└─%F{cyan}%# %f'
    fi
fi

### STRILOGGER END ###
EOFRC

    # Replace placeholder with actual log file
    sed -i "s|LOGFILE_PLACEHOLDER|$logfile|g" "$RC_FILE"
}

# Function to update tmux configuration
update_tmux_config() {
    local target_ip="${1:-N/A}"
    
    if [ -n "$TMUX" ]; then
        tmux set-option -g status-right "#[fg=yellow]Target: $target_ip #[fg=cyan]#(date -u +'%%H:%%M:%%S UTC') #[default]| %Y-%m-%d %H:%M" 2>/dev/null
        tmux set-option -g status-interval 1 2>/dev/null
        tmux set-hook -g window-linked "send-keys 'source $RC_FILE' Enter" 2>/dev/null
    fi
}

# Function to reload all shells
reload_all_shells() {
    if [ -n "$TMUX" ]; then
        echo -e "${CYAN}[+] Reloading all tmux panes...${RESET}"
        tmux list-panes -a -F "#{session_name}:#{window_index}.#{pane_index}" 2>/dev/null | while read -r pane_target; do
            tmux send-keys -t "$pane_target" "source $RC_FILE" Enter 2>/dev/null || true
            sleep 0.1
        done
        echo -e "${GREEN}[+] All panes reloaded${RESET}"
    fi
}

# Function to get next available filename with suffix
get_next_filename() {
    local base_logfile="$1"
    local counter=2
    local dir
    dir=$(dirname "$base_logfile")
    local filename
    filename=$(basename "$base_logfile" .log)
    local ip_pattern
    ip_pattern=$(echo "$filename" | sed -n 's/strilog_\([^_]*\)_.*/\1/p')
    local new_file="${dir}/strilog_${ip_pattern}_$(date -u '+%Y%m%d_%H%M%S')_${counter}.log"
    while [ -f "$new_file" ]; do
        counter=$((counter + 1))
        new_file="${dir}/strilog_${ip_pattern}_$(date -u '+%Y%m%d_%H%M%S')_${counter}.log"
    done
    echo "$new_file"
}

# Function to start logging
start_logging() {
    local ip="$1"
    local logfile=""
    local is_resume=false
    local existing_logfile=""
    if [ -z "$TMUX" ]; then
        echo -e "${RED}[!] ERROR: strilogger must be run inside a tmux session${RESET}"
        exit 1
    fi
    if [ -n "$ip" ]; then
        existing_logfile=$(get_logfile_for_ip "$ip")
        if [ -n "$existing_logfile" ] && [ -f "$existing_logfile" ]; then
            echo ""
            echo -e "${CYAN}Found existing log file for IP $ip:${RESET}"
            echo -e "  ${YELLOW}$existing_logfile${RESET}"
            echo ""
            echo -e "${GREEN}Choose an option:${RESET}"
            echo -e "  ${CYAN}1)${RESET} Resume logging to the same file"
            echo -e "  ${CYAN}2)${RESET} Create a new log file with suffix"
            echo -n "Enter choice (1 or 2): "
            read -r choice
            case "$choice" in
                1) logfile="$existing_logfile"; is_resume=true; echo -e "${GREEN}[+] Resuming to existing file...${RESET}" ;;
                2) logfile=$(get_next_filename "$existing_logfile"); echo -e "${GREEN}[+] Creating new file: $logfile${RESET}" ;;
                *) logfile="$existing_logfile"; is_resume=true; echo -e "${YELLOW}[!] Invalid choice. Defaulting to resume existing file.${RESET}" ;;
            esac
        fi
    fi
    if [ -f "$PID_FILE" ]; then
        local old_ip=""
        [ -f "$CURRENT_IP" ] && old_ip=$(cat "$CURRENT_IP")
        if [ "$old_ip" = "$ip" ] && [ "$is_resume" = true ]; then
            echo -e "${YELLOW}[!] Already logging to this IP's file${RESET}"
            return 0
        fi
        echo -e "${YELLOW}[+] Stopping existing logging session...${RESET}"
        stop_logging
        sleep 1
    fi
    if [ -z "$logfile" ]; then
        logfile=$(generate_logfile "$ip")
        {
            echo "==================== STRILOGGER SESSION START ===================="
            echo "Started: $(get_utc_timestamp)"
            [ -n "$ip" ] && echo "Target IP: $ip"
            echo "Log file: $logfile"
            echo "=================================================================="
            echo ""
        } > "$logfile"
        [ -n "$ip" ] && save_ip_mapping "$ip" "$logfile"
    else
        {
            echo ""
            echo "==================== LOGGING RESUMED ===================="
            echo "Resumed: $(get_utc_timestamp)"
            echo "========================================================="
            echo ""
        } >> "$logfile"
    fi
    echo "$logfile" > "$CURRENT_LOG"
    [ -n "$ip" ] && echo "$ip" > "$CURRENT_IP"
    update_tmux_config "$ip"
    add_hooks_to_rc "$logfile"
    reload_all_shells
    (while true; do sleep 3600; done) &
    local bg_pid=$!
    echo "$bg_pid" > "$PID_FILE"
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║         STRILOGGER STARTED SUCCESSFULLY                   ║${RESET}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${RESET}"
    echo -e "${CYAN}[+] Log file:${RESET} $logfile"
    [ -n "$ip" ] && echo -e "${CYAN}[+] Target IP:${RESET} $ip"
    echo -e "${CYAN}[+] Real-time capture:${RESET} ${GREEN}ACTIVE${RESET}"
    echo -e "${YELLOW}[+] UTC time visible in:${RESET} prompt and tmux status bar"
    echo -e "${YELLOW}[+] All current and future panes:${RESET} will log automatically"
    echo ""
}

case "$1" in
    stop) stop_logging ;;
    "") start_logging "" ;;
    *) start_logging "$1" ;;
esac
