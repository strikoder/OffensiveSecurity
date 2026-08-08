#!/bin/bash

# strilogger - tmux logging utility
# Usage: strilogger <IP> | strilogger stop

LOGDIR="$HOME/tmux-logs"
STATEFILE="$HOME/.strilogger_state"
HOOKFILE="$HOME/.strilogger_hook"
IP_MAP="$HOME/.strilogger_ipmap"
FILTER_SCRIPT="$HOME/.strilogger_filter.sh"

# Detect shell RC file
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    RC_FILE="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
    RC_FILE="$HOME/.bashrc"
else
    RC_FILE="$HOME/.bashrc"
fi

mkdir -p "$LOGDIR"

# Create a filter script to prevent recursive logging
create_filter_script() {
    local logfile="$1"
    cat > "$FILTER_SCRIPT" << 'EOFFILTER'
#!/bin/bash
LOGFILE="$1"
TEMP_BUFFER=""
LAST_LINE=""

while IFS= read -r line; do
    # Skip if this exact line was just written (prevents immediate echo loops)
    if [ "$line" = "$LAST_LINE" ]; then
        continue
    fi
    
    # Skip lines that are just reading the log file itself
    if echo "$line" | grep -qE "(cat|tail|less|more|head|vim|nano|vi).*(strilog_|tmux-logs)"; then
        continue
    fi
    
    # Write the line
    echo "$line" >> "$LOGFILE"
    LAST_LINE="$line"
done
EOFFILTER
    chmod +x "$FILTER_SCRIPT"
}

# Function to get all tmux panes
get_all_panes() {
    tmux list-panes -a -F "#{session_name}:#{window_index}.#{pane_index}"
}

# Function to start logging on all panes with filter
start_logging() {
    local logfile="$1"
    create_filter_script "$logfile"
    
    while IFS= read -r pane; do
        # Use the filter script to prevent recursive logging
        tmux pipe-pane -t "$pane" -o "$FILTER_SCRIPT '$logfile'" 2>/dev/null
    done < <(get_all_panes)
}

# Function to setup hook for new panes
setup_hook() {
    local logfile="$1"
    echo "$logfile" > "$HOOKFILE"
    tmux set-hook -g after-split-window "run-shell 'tmux pipe-pane -t \"#{pane_id}\" -o \"$FILTER_SCRIPT $logfile\"'" 2>/dev/null
    tmux set-hook -g after-new-window "run-shell 'tmux pipe-pane -t \"#{pane_id}\" -o \"$FILTER_SCRIPT $logfile\"'" 2>/dev/null
}

# Function to add UTC timestamp to prompt
add_utc_prompt() {
    # Remove old hooks if they exist
    if grep -q "### STRILOGGER UTC START ###" "$RC_FILE"; then
        sed -i '/### STRILOGGER UTC START ###/,/### STRILOGGER UTC END ###/d' "$RC_FILE"
    fi
    
    # Add new hooks
    cat >> "$RC_FILE" <<'EOFRC'

### STRILOGGER UTC START ###
# Static UTC timestamp - updates only on command execution
STRILOGGER_UTC=""

# Update timestamp before each command
strilogger_update_time() {
    STRILOGGER_UTC=$(date -u +'[%Y-%m-%d %H:%M:%S UTC]')
}

# Zsh prompt with UTC
if [ -n "$ZSH_VERSION" ]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec strilogger_update_time
    
    PROMPT='%F{blue}┌──(%B%F{red}%n@%m%b%F{blue})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{blue}] %F{yellow}${STRILOGGER_UTC}%f
%F{blue}└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
fi

# Bash prompt with UTC
if [ -n "$BASH_VERSION" ]; then
    strilogger_preexec_bash() {
        strilogger_update_time
    }
    trap 'strilogger_preexec_bash' DEBUG
    
    PS1='\[\033[01;34m\]┌──(\[\033[01;31m\]\u@\h\[\033[01;34m\])-[\[\033[00m\]\w\[\033[01;34m\]] \[\033[01;33m\]${STRILOGGER_UTC}\[\033[00m\]\n\[\033[01;34m\]└─\[\033[01;31m\]#\[\033[00m\] '
fi
### STRILOGGER UTC END ###
EOFRC
}

# Function to remove UTC prompt
remove_utc_prompt() {
    if [ -f "$RC_FILE" ]; then
        sed -i '/### STRILOGGER UTC START ###/,/### STRILOGGER UTC END ###/d' "$RC_FILE"
    fi
}

# Function to reload all shells
reload_all_shells() {
    if [ -n "$TMUX" ]; then
        echo "[+] Reloading all tmux panes..."
        tmux list-panes -a -F "#{session_name}:#{window_index}.#{pane_index}" 2>/dev/null | while read -r pane_target; do
            tmux send-keys -t "$pane_target" "source $RC_FILE" Enter 2>/dev/null || true
            sleep 0.1
        done
        echo "[+] All panes reloaded"
    fi
}

# Function to remove hooks
remove_hooks() {
    tmux set-hook -gu after-split-window 2>/dev/null
    tmux set-hook -gu after-new-window 2>/dev/null
    rm -f "$HOOKFILE"
    rm -f "$FILTER_SCRIPT"
}

# Function to stop logging on all panes
stop_logging() {
    while IFS= read -r pane; do
        tmux pipe-pane -t "$pane" 2>/dev/null
    done < <(get_all_panes)
    remove_hooks
    remove_utc_prompt
    reload_all_shells
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
    if [ -f "$IP_MAP" ]; then
        grep -v "^${ip}:" "$IP_MAP" > "$IP_MAP.tmp" 2>/dev/null || true
        mv "$IP_MAP.tmp" "$IP_MAP"
    fi
    echo "${ip}:${logfile}" >> "$IP_MAP"
}

# Function to get next available filename
get_next_filename() {
    local base_logfile="$1"
    local counter=2
    local new_file="${base_logfile%.log}_${counter}.log"
    while [ -f "$new_file" ]; do
        counter=$((counter + 1))
        new_file="${base_logfile%.log}_${counter}.log"
    done
    echo "$new_file"
}

# Handle stop command
if [ "$1" == "stop" ]; then
    if [ ! -f "$STATEFILE" ]; then
        echo "No active logging session found."
        exit 1
    fi
    
    stop_logging
    current_log=$(cat "$STATEFILE")
    rm -f "$STATEFILE"
    echo "Stopped logging to: $current_log"
    echo "UTC timestamp removed from prompt."
    exit 0
fi

# Validate IP argument
if [ -z "$1" ]; then
    echo "Usage: strilogger <IP> | strilogger stop"
    exit 1
fi

IP="$1"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
BASE_LOGFILE="$LOGDIR/${TIMESTAMP}_${IP}.log"
LOGFILE="$BASE_LOGFILE"

# Check if there's an existing log for this IP
existing_logfile=$(get_logfile_for_ip "$IP")

if [ -n "$existing_logfile" ] && [ -f "$existing_logfile" ]; then
    echo ""
    echo "Found existing log for $IP:"
    echo "  $existing_logfile"
    echo ""
    read -p "Continue in existing file (c) or create new file (n)? [c/n]: " choice
    
    case "$choice" in
        c|C|"")
            LOGFILE="$existing_logfile"
            echo "Continuing in: $LOGFILE"
            ;;
        n|N)
            LOGFILE=$(get_next_filename "$BASE_LOGFILE")
            echo "Creating new file: $LOGFILE"
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
fi

# Stop any existing logging
if [ -f "$STATEFILE" ]; then
    old_log=$(cat "$STATEFILE")
    stop_logging
    echo "Stopped previous logging to: $old_log"
fi

# Start logging
echo "========== Logging started at $(date -u) ==========" >> "$LOGFILE"
start_logging "$LOGFILE"
setup_hook "$LOGFILE"
add_utc_prompt
save_ip_mapping "$IP" "$LOGFILE"
echo "$LOGFILE" > "$STATEFILE"

# Reload shells AFTER starting logging to avoid capturing the reload messages
sleep 0.5
reload_all_shells

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         STRILOGGER STARTED SUCCESSFULLY                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo "[+] Log file: $LOGFILE"
echo "[+] Target IP: $IP"
echo "[+] All current and future tmux panes will be logged."
echo "[+] UTC timestamp added to prompt."
echo "[+] Use 'strilogger stop' to stop logging."
echo ""
