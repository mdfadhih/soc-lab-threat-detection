# Incident Report — IR-002
## Suspicious Scheduled Task Creation

| Field | Details |
|-------|---------|
| **Date** | 2026-06-08 |
| **Severity** | High |
| **Status** | Resolved |
| **Analyst** | Mohamed Fadhih |
| **MITRE ATT&CK** | T1053 — Scheduled Task/Job |
| **Tactic** | Persistence |
| **Detection Rule** | rule2-scheduled-task.kql |

---

## 1. Preparation

- **Detection tool:** Microsoft Sentinel — KQL query on SecurityEvent table
- **Log source:** Windows Security Event Log (EventID 4688)
- **Audit policy required:** Process Creation auditing + command line logging enabled
- **Workspace:** law-soc-lab (Azure Australia Southeast)

---

## 2. Identification

**Alert triggered:** Scheduled task creation detected with suspicious PowerShell command in task action

**Evidence:**
- Task name: WindowsUpdateHelper (masquerading as legitimate Windows task)
- Task action: `powershell.exe -WindowStyle Hidden`
- Scheduled: Daily at 03:00 — chosen to avoid detection during off-hours
- Created by: labadmin account
- Workstation: vm-windows-target

**KQL query used:**
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4688, 4698)
| where CommandLine has_any ("schtasks","powershell","hidden")
| project TimeGenerated, Computer, Account, CommandLine
```

**Scope assessment:** Single workstation. Task created but no evidence of execution or network callback. No child processes spawned from the scheduled task.

**Indicators of compromise:**
- Hidden PowerShell window flag (`-WindowStyle Hidden`) — evasion technique
- Task name designed to blend with legitimate Windows tasks
- Scheduled during off-hours (03:00) to avoid analyst visibility

---

## 3. Containment

**Immediate actions:**
- Delete the suspicious scheduled task immediately
- Review all scheduled tasks on the affected host for similar patterns
- Check for other persistence mechanisms (registry run keys, startup folder)

```cmd
schtasks /delete /tn "WindowsUpdateHelper" /f
```

---

## 4. Eradication

- Suspicious scheduled task deleted and confirmed removed
- No additional persistence mechanisms found
- No malware payload identified — task action pointed to non-existent URL
- Reviewed all scheduled tasks — no other anomalies found

---

## 5. Recovery

- Re-image workstation if malware execution is confirmed in production
- Audit all scheduled tasks across the environment using:
```powershell
Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*powershell*"}
```
- Implement application whitelisting to prevent unauthorised script execution
- Enable PowerShell Script Block Logging for deeper visibility

---

## 6. Lessons Learned

- Task Scheduler audit policy (EventID 4698) must be explicitly enabled — not on by default
- Attackers commonly name persistence tasks to mimic legitimate Windows services
- Off-hours scheduling (03:00) is a common evasion technique — after-hours alerting is essential
- Command line logging is critical for detecting PowerShell-based persistence

---

## Timeline

| Time | Event |
|------|-------|
| T+0:00 | schtasks.exe executed — EventID 4688 generated |
| T+0:01 | Suspicious command line flags detected by KQL rule |
| T+0:05 | Analyst reviews task details — confirms suspicious naming convention |
| T+0:15 | Task deleted — eradication complete |
| T+0:30 | Full task audit complete — no other anomalies |
| T+0:45 | Incident closed — no execution confirmed |
