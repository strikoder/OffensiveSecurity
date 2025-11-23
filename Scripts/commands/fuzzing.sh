#!/bin/bash

echo "(hint) run nikto or nuclei if stuck:"
echo "nikto -h \$IP -p 433,1433,80"
echo "nuclei -target http://\$IP"
echo ""
echo "========================================"
echo ""

# Directory fuzzing with different wordlists
echo "ffuf -u http://\$IP/FUZZ -w \$raft_dir -t 300"
echo "ffuf -u http://\$IP/FUZZ -w \$dirb -t 300"
echo "ffuf -u http://\$IP/FUZZ -w \$dir_list -t 300"
echo ""

# File fuzzing with PHP extension
echo "ffuf -u http://\$IP:5002/FUZZ -w \$raft_files -e .php"
echo ""

# API endpoint fuzzing
echo "ffuf -u http://\$IP:5002/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt"
echo ""

# Pattern-based fuzzing
echo "# or if we see a specific pattern: vim pattern.txt"
echo "# {GOBUSTER}/v1"
echo "# {GOBUSTER}/v2"
echo ""
echo "gobuster dir -u http://\$IP:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt"
echo ""

# VHost fuzzing
echo "#vhost:"
echo "ffuf -H \"Host: FUZZ.website.com\" -H \"User-Agent: PENTEST\" -c -w \"/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt\" -u http://website.com"
echo ""

# DNS fuzzing placeholder
echo "#dns"
echo "gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/namelist.txt"
echo "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H \"Host: FUZZ.acmeitsupport.thm\" -u http://10.10.227.197 -fs [size] (brute forcing sub domains)"
echo "dnsenum <domain>"

