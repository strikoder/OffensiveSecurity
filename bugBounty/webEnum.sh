#!/bin/bash

# === [ Input Check ] ===
url=$1
if [ -z "$url" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

# === [ Dependency Check ] ===
REQUIRED_TOOLS=(subfinder amass findomain dnsx httpx gowitness subjack waybackurls whatweb)
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v $tool &> /dev/null; then
    echo "[-] $tool is required but not installed."
    exit 1
  fi
done

# === [ Dir Setup ] ===
mkdir -p $url/recon/{scans,httprobe,potential_takeovers,wayback/{params,extensions},whatweb,gowitness,thirdlvl}
> $url/recon/httprobe/alive.txt
> $url/recon/final.txt

# === [ Subdomain Enumeration ] ===
echo "[+] Running subfinder, amass, and findomain..."
subfinder -d $url -silent >> $url/recon/final.txt
amass enum -passive -d $url >> $url/recon/final.txt
findomain -t $url -q >> $url/recon/final.txt
sort -u $url/recon/final.txt -o $url/recon/final.txt

# === [ 3rd Level Domains ] ===
echo "[+] Extracting 3rd-level domains..."
cat $url/recon/final.txt | grep -Po '([\w.-]+\.[\w-]+\.[\w-]+)$' | sort -u > $url/recon/thirdlvl/3rdlvl.txt

# === [ Subdomain Enumeration for 3rd Levels ] ===
echo "[+] Running sublist3r on 3rd-level domains..."
for domain in $(cat $url/recon/thirdlvl/3rdlvl.txt); do
  sublist3r -d $domain -o $url/recon/thirdlvl/$domain.txt
  cat $url/recon/thirdlvl/$domain.txt >> $url/recon/final.txt
  sort -u $url/recon/final.txt -o $url/recon/final.txt
  done

# === [ DNS Resolution + HTTP Probing ] ===
echo "[+] Validating DNS with dnsx..."
dnsx -silent -l $url/recon/final.txt > $url/recon/httprobe/resolved.txt

echo "[+] Probing HTTP services with httpx..."
httpx -silent -l $url/recon/httprobe/resolved.txt | sed 's|https\?://||g' | sort -u > $url/recon/httprobe/alive.txt

echo "========================================"
echo "Hint: search for stag, admin, dev, test in alive.txt"
echo "========================================"

# === [ Subdomain Takeover Check ] ===
echo "[+] Checking for subdomain takeover with subjack..."
subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl \
  -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 \
  -o $url/recon/potential_takeovers/potential_takeovers.txt

# === [ WhatWeb Analysis ] ===
echo "[+] Scanning with WhatWeb..."
for domain in $(cat $url/recon/httprobe/alive.txt); do
  mkdir -p $url/recon/whatweb/$domain
  whatweb --info-plugins -t 50 -v $domain > $url/recon/whatweb/$domain/plugins.txt
  whatweb -t 50 -v $domain > $url/recon/whatweb/$domain/output.txt
  sleep 3
done

# === [ Wayback Machine Collection ] ===
echo "[+] Collecting Wayback URLs..."
waybackurls < $url/recon/final.txt | sort -u > $url/recon/wayback/wayback_output.txt

# === [ Wayback Param Extraction ] ===
echo "[+] Extracting parameters from Wayback..."
grep -oP '\?.*?=' $url/recon/wayback/wayback_output.txt | cut -d '=' -f 1 | sort -u > $url/recon/wayback/params/wayback_params.txt

# === [ Extension Filtering ] ===
echo "[+] Extracting file types from Wayback..."
while read line; do
  ext="${line##*.}"
  case "$ext" in
    js) echo $line >> $url/recon/wayback/extensions/js.txt;;
    html|jsp) echo $line >> $url/recon/wayback/extensions/jsp.txt;;
    json) echo $line >> $url/recon/wayback/extensions/json.txt;;
    php) echo $line >> $url/recon/wayback/extensions/php.txt;;
    aspx) echo $line >> $url/recon/wayback/extensions/aspx.txt;;
  esac
done < $url/recon/wayback/wayback_output.txt

# === [ Port Scanning ] ===
#echo "[+] Scanning ports with nmap..."
# nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned
echo "[+] Scanning ports with nmap is commented out for time purposes, if you have time, uncomment and let it scans..."


# === [ Screenshots ] ===
echo "[+] Capturing screenshots with GoWitness..."
gowitness file -f $url/recon/httprobe/alive.txt \
  --timeout 5 --threads 10 --log-level error \
  --destination $url/recon/gowitness

echo "[✓] Recon complete for $url."
echo
echo "[ℹ️] Recon complete. Check the following directories:"
echo "   ├─ $url/recon/final.txt                 → All discovered subdomains"
echo "   ├─ $url/recon/httprobe/alive.txt        → DNS-resolved & alive HTTP(s) hosts"
echo "   ├─ $url/recon/potential_takeovers/      → Possible subdomain takeover info"
echo "   ├─ $url/recon/wayback/wayback_output.txt→ Archived URLs from Wayback Machine"
echo "   ├─ $url/recon/wayback/params/           → Possible URL parameters"
echo "   ├─ $url/recon/wayback/extensions/       → Interesting files (js, json, php, etc.)"
echo "   ├─ $url/recon/scans/scanned.*           → Nmap port scan results"
echo "   ├─ $url/recon/gowitness/                → Screenshots of alive hosts"
echo "   ├─ $url/recon/whatweb/                  → Tech fingerprinting results"
echo "   ├─ $url/recon/thirdlvl/                 → 3rd-level subdomains enumerated"
echo
echo "[✓] All recon data saved under: $url/recon/"

exit 0
