#!/bin/bash
set -euo pipefail
ZSHRC="$HOME/.zshrc"
TMUXCONF="$HOME/.tmux.conf"

# ====================================
# ======= ZSH HISTORY SETTINGS =======
# ====================================

# --- Overwrite Zsh history settings in ~/.zshrc ---
echo -e "\n[+] Configuring history settings in ~/.zshrc..."
# Remove any existing HISTSIZE, SAVEHIST, or history-related setopt lines
sed -i '/^HISTSIZE=/d' "$ZSHRC"
sed -i '/^SAVEHIST=/d' "$ZSHRC"
sed -i '/^setopt *SHARE_HISTORY/d' "$ZSHRC"

# Append the clean block
cat << 'EOF' >> ~/.zshrc

# History configuration
HISTSIZE=100000
SAVEHIST=100000
setopt APPEND_HISTORY
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY
EOF

# ====================================
# TMUX SHARED ENV HELPERS (in ZSHRC)
# ====================================

# --- Install shared env + envset/envunset/envload (idempotent via markers) ---
echo -e "\n[+] Installing tmux-shared-env helpers into ~/.zshrc..."

cat << 'EOF' >> "$ZSHRC"

# >>> tmux-shared-env >>>
# Persistent, tmux-synchronized environment helpers

# File to persist shared exports
export SHARED_ENV="$HOME/.shared_env"
[[ -f "$SHARED_ENV" ]] || : > "$SHARED_ENV"
# Always load it for new shells
source "$SHARED_ENV"

envset() {
  emulate -L zsh
  local pair var val esc self
  # Current tmux pane (if inside tmux); empty otherwise
  self=$(tmux display -p '#{pane_id}' 2>/dev/null || true)

  for pair in "$@"; do
    if [[ "$pair" != *=* ]]; then
      print -u2 "envset: expected VAR=value, got '$pair'"
      continue
    fi

    var="${pair%%=*}"
    val="${pair#*=}"

    # 1) Export in current shell
    export "$var=$val"

    # 2) Persist (dedupe) in SHARED_ENV
    #    Remove any previous export of the same var, then append safely quoted value
    sed -i.bak "/^export[[:space:]]\+$var=/d" "$SHARED_ENV" 2>/dev/null || true
    printf 'export %s=%q\n' "$var" "$val" >> "$SHARED_ENV"

    # 3) Propagate to tmux: new panes + existing panes (skip current)
    if command -v tmux >/dev/null 2>&1 && tmux display -p '#{session_id}' >/dev/null 2>&1; then
      tmux setenv -g "$var" "$val"  # new panes/windows inherit
      esc=${(q)val}                 # zsh-safe quoting
      tmux list-panes -a -F '#{pane_id}' 2>/dev/null | while read -r p; do
        [[ -n "$self" && "$p" == "$self" ]] && continue
        tmux send-keys -t "$p" "export $var=$esc" C-m
      done
    fi
  done
}

envunset() {
  emulate -L zsh
  local var self
  self=$(tmux display -p '#{pane_id}' 2>/dev/null || true)

  for var in "$@"; do
    unset "$var"
    sed -i.bak "/^export[[:space:]]\+$var=/d" "$SHARED_ENV" 2>/dev/null || true
    if command -v tmux >/dev/null 2>&1 && tmux display -p '#{session_id}' >/dev/null 2>&1; then
      tmux setenv -gu "$var" 2>/dev/null || true
      tmux list-panes -a -F '#{pane_id}' 2>/dev/null | while read -r p; do
        [[ -n "$self" && "$p" == "$self" ]] && continue
        tmux send-keys -t "$p" "unset $var" C-m
      done
    fi
  done
}

envload() {
  emulate -L zsh
  local self
  [[ -f "$SHARED_ENV" ]] && source "$SHARED_ENV"
  self=$(tmux display -p '#{pane_id}' 2>/dev/null || true)
  if command -v tmux >/dev/null 2>&1 && tmux display -p '#{session_id}' >/dev/null 2>&1; then
    tmux list-panes -a -F '#{pane_id}' 2>/dev/null | while read -r p; do
      [[ -n "$self" && "$p" == "$self" ]] && continue
      tmux send-keys -t "$p" "source $SHARED_ENV" C-m
    done
  fi
}

alias exportall='envset'
# <<< tmux-shared-env <<<
EOF


# --- Append tmux auto-launch to ~/.zshrc ---
echo -e "\n[+] Appending tmux auto-launch to ~/.zshrc..."
cat << 'EOF' >> ~/.zshrc

# Auto-start tmux with vertical split on login
if command -v tmux &> /dev/null && [ -z "$TMUX" ]; then
    tmux has-session -t main 2>/dev/null || {
        tmux new-session -d -s main
    }
    tmux attach-session -t main
fi
EOF

# ====================================
# =========== TMUX.CONF ==============
# ====================================

# --- Write ~/.tmux.conf ---
echo -e "\n[+] Writing tmux configuration to ~/.tmux.conf..."
cat << 'EOF' > ~/.tmux.conf
# Prefix Key
unbind C-b
set -g prefix C-s
bind C-s send-prefix

# Mouse and Clipboard
set -g mouse on
set -g set-clipboard on

# Function Key Window Shortcuts
bind-key -n F1 select-window -t :1
bind-key -n F2 select-window -t :2
bind-key -n F3 select-window -t :3
bind-key -n F4 select-window -t :4
bind-key -n F5 select-window -t :0

# Status Bar
set -g status-right "Strikoder"
setw -g synchronize-panes on
EOF

# --- Fix vim clipboard ---
echo -e "\n[+] Enabling system clipboard for Vim..."
echo "set clipboard=unnamedplus" | sudo tee -a /etc/vim/vimrc > /dev/null

# --- Keyboard shortcut reminder ---
echo -e "\n[!] Don’t forget to configure keyboard shortcuts under:"
echo -e "    Settings > Keyboard > Shortcuts > Navigation"
echo -e "    Super+1 = Switch to Workspace 1"
echo -e "    Super+2 = Switch to Workspace 2"
echo -e "    Ctrl+Super+1 = Move window to Workspace 1"
echo -e "    Ctrl+Super+2 = Move window to Workspace 2"

# --- Add common pentesting wordlist environment variables ---
echo -e "\n[+] Adding pentesting wordlist environment variables..."
cat << 'EOF' >> "$ZSHRC"

# >>> pentesting wordlists >>>
envset dirb=/usr/share/wordlists/dirb/big.txt
envset raft_dir=/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
envset dir_list=/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
envset rockyou=/usr/share/wordlists/rockyou.txt
# <<< pentesting wordlists <<<
EOF
