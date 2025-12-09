# Offensive Security Automation Scripts

Bash scripts for automating Active Directory enumeration and attacks during penetration testing. Scripts don't have the `.sh` extension for direct terminal execution.

---

## 📁 Repository Structure

- **`/enum`** - SMB, LDAP, Kerberos, and DNS enumeration (authenticated & unauthenticated)
- **`/commands`** - Utility scripts for credential management, payloads, shells, and fuzzing

---

## 🔎 Enumeration Scripts (`/enum`)

### SMB

**`noauth_smb <IP>`**
- Unauthenticated SMB enumeration (null/anonymous/guest)
- RID brute force, share permissions, vulnerability scanning
- Better than smbmap/enum4linux-ng (test on Blackfield HTB!)

**`auth_smb -t <IP> -u <user> [-p <pass> | -H <hash>] [-d <domain>]`**
- Authenticated SMB enumeration with domain/local auth
- Share crawling, DPAPI, credential dumping modules
- Omit `-d` for local authentication

### LDAP

**`noauth_ldap <IP> <domain> [-ldaps]`**
- Anonymous LDAP enumeration
- Extracts users, info attributes, UAC flags, cascadeLegacy passwords

**`auth_ldap <IP> <user> [-p <pass> | -H <hash>] <domain> [-ldaps]`**
- Authenticated LDAP queries with full user attribute dumps
- AS-REP roasting, Kerberoasting, LAPS enumeration

### Kerberos

**`noauth_kerberos <DC_IP> <domain>`**
- Kerbrute user enumeration
- AS-REP roasting with wordlist

**`auth_kerberos -u <user> [-p <pass> | -H <hash>] -i <DC_IP> -d <domain>`**
- Authenticated AS-REP roasting
- Kerberoasting (GetUserSPNs)

### DNS

**`noauth_dns <DNS_IP> <domain> [wordlist.txt]`**
- DNS enumeration (SOA, NS, MX, TXT, SRV records)
- Zone transfer attempts (AXFR)
- Subdomain brute forcing with wordlist

---

## 🛠️ Utility Scripts (`/commands`)

**`cred_validator`**
- Multi-protocol credential validation (SMB, WinRM, RDP, MSSQL, FTP, SSH, LDAP)
- Spray mode (all users × all passwords) or no-spray mode (paired credentials)
- Auto-detects passwords vs NTLM hashes

**`revshell_gen`**
- Interactive reverse shell payload generator
- Linux: bash, netcat, python, perl, php, ruby (with base64 encoding)
- Windows: PowerShell, Powercat, nc.exe (download + execute or in-memory)

**`ad_vuln_check <DC_hostname> <DC_IP>`**
- Quick vulnerability checks: Zerologon, PrintNightmare

**`addhost <IP> <hostname1> [hostname2] ...`**
- Add/update `/etc/hosts` entries

**`lin_stable_shell`**
- Linux TTY upgrade cheatsheet

**`export_creds <file>`**
- Parse credential files and export as shell variables (`user1`, `pass1`, etc.)

**`http_server`**
- Start Python HTTP server with tun0 IP and wget commands

**`web_fuzz_hints`**
- Common ffuf/gobuster commands for web fuzzing

**`help`**
- Display all available custom commands


---

## 📝 Notes

- All enumeration results are saved to `results_*` directories with timestamps
- Hash authentication supported where applicable (pass-the-hash)
- Scripts include hints for cracking hashes and next steps
- Designed for authorized penetration testing only
