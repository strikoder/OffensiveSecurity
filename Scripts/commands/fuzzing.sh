#!/bin/bash

cat << 'EOF'

#don't forget to read the source code
nikto -h $IP -p 433,1433,80
nuclei -fr -target http://$IP
nuclei -fr -target http://$IP -headless
wapplyzer
========================================

ffuf -u http://$IP/FUZZ -w $raft_dir -t 300
ffuf -u http://$IP/FUZZ -w $dirb -t 300
ffuf -u http://$IP/FUZZ -w $dir_list -t 300
/opt/SecLists/Discovery/Web-Content/spring-boot.txt 

ffuf -u http://$IP:5002/FUZZ -w $raft_files -e .php

ffuf -u http://$IP:5002/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt

# or if we see a specific pattern: vim pattern.txt
# {GOBUSTER}/v1
# {GOBUSTER}/v2

gobuster dir -u http://$IP:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt

#vhost:
ffuf -u https://$IP -H "Host: FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --fc 301 -t 300
wfuzz -u http://$IP/ -H "Host: FUZZ.oniichan.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 28 -t 50

#dns
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/namelist.txt
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.227.197 -fs [size] (brute forcing sub domains)
dnsenum <domain>
noauth_dns $IP

EOF
