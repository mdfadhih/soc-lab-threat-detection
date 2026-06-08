# MITRE ATT&CK Coverage Map

## Tactics Covered

### Credential Access
| Technique | ID | Detection Rule | EventID | Severity |
|-----------|-----|---------------|---------|----------|
| Brute Force | T1110 | rule1-brute-force.kql | 4625 | High |

### Persistence
| Technique | ID | Detection Rule | EventID | Severity |
|-----------|-----|---------------|---------|----------|
| Scheduled Task/Job | T1053 | rule2-scheduled-task.kql | 4688/4698 | High |

### Discovery
| Technique | ID | Detection Rule | EventID | Severity |
|-----------|-----|---------------|---------|----------|
| Account Discovery | T1087 | rule3-account-enumeration.kql | 4688 | Medium |

### Execution
| Technique | ID | Detection Rule | EventID | Severity |
|-----------|-----|---------------|---------|----------|
| PowerShell | T1059.001 | rule4-suspicious-powershell.kql | 4688 | High |

### Defense Evasion / Persistence
| Technique | ID | Detection Rule | EventID | Severity |
|-----------|-----|---------------|---------|----------|
| Valid Accounts | T1078 | rule5-after-hours-login.kql | 4624 | Medium |

---

## Windows Event ID Reference

| EventID | Description | Used In |
|---------|-------------|---------|
| 4624 | Successful logon | Rule 5 |
| 4625 | Failed logon | Rule 1 |
| 4688 | Process creation | Rules 2, 3, 4 |
| 4698 | Scheduled task created | Rule 2 |

---

## Audit Policies Required

Enable these on the target Windows VM:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Task Scheduler" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable

# Enable command line logging
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```
