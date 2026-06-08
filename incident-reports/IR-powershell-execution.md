# Incident Report — IR-003
## Suspicious PowerShell Execution

| Field | Details |
|-------|---------|
| **Date** | 2026-06-08 |
| **Severity** | High |
| **Status** | Resolved |
| **Analyst** | Mohamed Fadhih |
| **MITRE ATT&CK** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Detection Rule** | rule4-suspicious-powershell.kql |

---

## 1. Preparation

- **Detection tool:** Microsoft Sentinel — KQL query on SecurityEvent table
- **Log source:** Windows Security Event Log (EventID 4688)
- **Prerequisites:** Command line auditing enabled via registry
- **Workspace:** law-soc-lab (Azure Australia Southeast)

---

## 2. Identification

**Alert triggered:** PowerShell execution detected with execution policy bypass and hidden window flags

**Evidence:**
- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Flags detected: `-ExecutionPolicy bypass`, `-WindowStyle Hidden`
- Account: vm-windows-targ\labadmin
- Workstation: vm-windows-target
- Time: 2026-06-08 05:53:05 UTC (15:53 AEST)
- Multiple PowerShell instances spawned in short succession

**KQL query used:**
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| where NewProcessName has "powershell"
| where CommandLine has_any ("bypass","hidden","IEX","DownloadString")
| project TimeGenerated, Computer, Account, CommandLine
```

**Results:** 4 PowerShell execution events detected within 15-minute window

**Scope assessment:** Single workstation. PowerShell commands executed interactively — no evidence of encoded commands or network downloads. No child process spawning suspicious executables.

**Risk factors:**
- `-ExecutionPolicy bypass` overrides system security policy
- `-WindowStyle Hidden` actively conceals execution from users
- Multiple rapid executions suggest scripted or automated activity

---

## 3. Containment

**Immediate actions:**
- Identify all PowerShell processes currently running on affected host
- Capture memory dump if malicious payload suspected in production
- Isolate host from network if active C2 communication detected

```powershell
# Check running PowerShell processes
Get-Process powershell | Select-Object Id, StartTime, CPU
# Check PowerShell history
Get-Content (Get-PSReadLineOption).HistorySavePath
```

---

## 4. Eradication

- No malicious payload identified — commands were part of controlled simulation
- PowerShell execution history reviewed — no encoded or obfuscated commands found
- No network connections established during PowerShell execution
- No files dropped or registry modifications made

---

## 5. Recovery

- Implement PowerShell Constrained Language Mode for non-admin users
- Enable PowerShell Script Block Logging (EventID 4104) for full command visibility:
```powershell
# Enable Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```
- Consider deploying PowerShell Just Enough Administration (JEA)
- Review and tighten execution policy across all endpoints

---

## 6. Lessons Learned

- Command line logging (registry key) is essential — EventID 4688 alone is insufficient without it
- `-ExecutionPolicy bypass` and `-WindowStyle Hidden` are reliable indicators of suspicious PowerShell
- Script Block Logging (EventID 4104) would provide deeper visibility into actual commands executed
- Correlating PowerShell execution with network connections strengthens detection confidence

---

## Timeline

| Time | Event |
|------|-------|
| T+0:00 | First PowerShell process spawned with bypass flag |
| T+0:02 | Second instance with -WindowStyle Hidden detected |
| T+0:05 | KQL rule triggers — 3+ suspicious PowerShell events |
| T+0:10 | Analyst reviews CommandLine fields — confirms suspicious flags |
| T+0:20 | Process investigation complete — no payload identified |
| T+0:30 | Recommendations issued — Script Block Logging recommended |
| T+0:45 | Incident closed — controlled simulation confirmed |
