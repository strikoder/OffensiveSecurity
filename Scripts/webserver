#!/usr/bin/env bash
set -euo pipefail

# 1) get tun0 ip and print
ip=$(ip a show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d'/' -f1 || true)
echo "your local host is:"
if [ -n "$ip" ]; then
  echo "$ip"
else
  echo "(no tun0 found)"
fi


# 2) plain ls (no flags)
ls

# 3) echo certutil commands for all files in the directory
files=(*)  # non-hidden items
if [ "${#files[@]}" -eq 0 ]; then
  echo "No files found."
else
  for f in "${files[@]}"; do
    [ -d "$f" ] && continue  # skip directories
    echo "wget http://$ip/$f"
  done
fi

# 4) run simple HTTP server as requested
sudo python3 -m http.server 80
