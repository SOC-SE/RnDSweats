# Kerberos Key Rotation (Golden Ticket Mitigation)

## Purpose

This directory contains tools for rotating the `krbtgt` account password to invalidate **Golden Tickets** after an Active Directory compromise.

## What is a Golden Ticket?

A Golden Ticket is a forged Kerberos TGT (Ticket Granting Ticket) created by an attacker who has obtained the `krbtgt` account's password hash. With a Golden Ticket, an attacker can:
- Impersonate any user in the domain
- Access any resource
- Maintain persistent access even after password changes

## Mitigation

The only way to invalidate Golden Tickets is to reset the `krbtgt` password **twice** (because Kerberos keeps the current and previous password for compatibility).

**IMPORTANT**: Wait for replication between password resets. The recommended wait time is at least 10 hours (default Kerberos ticket lifetime).

## Required Script

### New-KrbtgtKeys.ps1 (Microsoft Official)

**Source**: https://github.com/microsoft/New-KrbtgtKeys.ps1

**Download**:
```powershell
# Clone the repository
git clone https://github.com/microsoft/New-KrbtgtKeys.ps1.git

# Or download directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/New-KrbtgtKeys.ps1/master/New-KrbtgtKeys.ps1" -OutFile "New-KrbtgtKeys.ps1"
```

### Script Modes

| Mode | Description |
|------|-------------|
| 1 | Informational - Shows current state, no changes |
| 2 | Simulation with canary object - Tests replication |
| 3 | Simulation with TEST krbtgt accounts |
| 4 | **PRODUCTION** - Resets actual krbtgt password |
| 8 | Create TEST krbtgt accounts |
| 9 | Delete TEST krbtgt accounts |

## Usage for Competition

### Quick Reference (AFTER Compromise Confirmed)

```powershell
# 1. First, run in informational mode to see current state
.\New-KrbtgtKeys.ps1
# Select Mode 1

# 2. Create TEST accounts first (recommended)
.\New-KrbtgtKeys.ps1
# Select Mode 8

# 3. Test with simulation mode
.\New-KrbtgtKeys.ps1
# Select Mode 3

# 4. If simulation successful, perform FIRST real reset
.\New-KrbtgtKeys.ps1
# Select Mode 4

# 5. WAIT at least 10 hours for replication and ticket expiry

# 6. Perform SECOND reset to fully invalidate Golden Tickets
.\New-KrbtgtKeys.ps1
# Select Mode 4
```

### Competition Shortcut (Emergency)

If you're in competition and need to invalidate Golden Tickets immediately:

```powershell
# WARNING: May cause temporary authentication issues!
# Only use if you've confirmed Golden Ticket attack

# Reset krbtgt password (first time)
.\New-KrbtgtKeys.ps1
# Select Mode 4, confirm prompts

# Wait 10-20 minutes for replication

# Reset krbtgt password (second time)
.\New-KrbtgtKeys.ps1
# Select Mode 4, confirm prompts
```

**Note**: In competition, the 10-hour wait may not be practical. A shorter wait (10-20 minutes) will invalidate most tickets, but some long-lived tickets may still work until they expire.

## Requirements

- Domain Admin or Enterprise Admin privileges
- Run from a Domain Controller or domain-joined machine
- PowerShell with RSAT-AD-PowerShell module
- Connectivity to all DCs for replication monitoring

## Related Scripts

- `Clear-KrbClientCachesForAllSessions.ps1` - Clears Kerberos ticket caches on clients (run after krbtgt reset if experiencing auth issues)

## References

- [Microsoft Security Blog - KrbTgt Account Password Reset](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/)
- [AD Forest Recovery - Resetting krbtgt Password](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
- [Detecting Golden Ticket Attacks](https://adsecurity.org/?p=1515)

## Quick Validation

After resetting, verify with:

```powershell
# Check krbtgt last password change
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet

# Check replication status
repadmin /showrepl
```
