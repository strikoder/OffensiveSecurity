========================================
Active Directory Enumeration Methodology
========================================

=== NO CREDENTIALS ===

# Run your custom enumeration scripts
noauth_smb
noauth_ldap
noauth_kerberos
noauth_dns

========================================

=== WITH CREDENTIALS ===

# Run your custom enumeration scripts
auth_smb
auth_ldap
auth_kerberos

========================================

=== BLOODHOUND DATA COLLECTION ===

# SharpHound (Windows)
.\SharpHound.exe -c All -d domain.local --zipfilename output.zip
.\SharpHound.exe -c DCOnly

# RustHound (Linux)
/usr/local/bin/mycommands/methodology: line 50: syntax error near unexpected token `('
/usr/local/bin/mycommands/methodology: line 50: `echo "# Snaffler (File/Share Hunting)"'
