# SMB Enumeration Scripts (by strikoder)

This repo contains three Bash scripts for automating **SMB enumeration and attacks**.  
Scripts don’t have the `.sh` extension so they can be called directly from the terminal.

---

## 🔎 1. `no_auth_smb`
Enumerates SMB services with **no authentication** (null, anonymous, guest).

- It's way better than smbmap and enum4linux-ng, check for instance blackfield htb and try to run them against the machine, u could only find the users using the nxc --rid-brute
- Runs safe Nmap SMB scripts
- Lists shares via `smbclient`
- Runs `rpcclient` null queries
- Uses `nxc` with null/anonymous/guest
- Runs `enum4linux-ng`
- Uses `smbmap` for share permissions & listings
- Fallback listing with `smbclient`
- Auto-loots interesting files with `smbget`
- Greps listings for credential keywords
- Tests SMB dialects (SMB3/2/NT1)

---

## 🔑 2. `auth_smb`
Enumerates SMB with **valid credentials**.

- Uses `nxc` with auth for:
  - Shares, users, groups, pass policy
  - Logged-on users, qwinsta sessions
  - GPP passwords, WDigest, Zerologon
- DPAPI extractions (`--dpapi`, `cookies`, `nosystem`, `--local-auth`)
- Runs modules (if supported):
  - `spider_plus`, `sam`, `lsa`, `lsass`, `putty`,  
    `backup_operator`, `ldapi`, `rdcman`
- Saves all outputs per target with timestamp



## 🚀 Usage
```bash
# No-auth enumeration
./no_auth_smb $IP

# Authenticated enumeration
./auth_smb -t $IP -u <user> -p <pass> [-d <domain>] [--local-auth]
```
