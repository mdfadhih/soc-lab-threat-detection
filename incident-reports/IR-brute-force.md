# Incident Report — IR-001
## Multiple Failed Authentication Attempts (Brute Force)

| Field | Details |
|-------|---------|
| **Date** | 2026-06-08 |
| **Severity** | High |
| **Status** | Resolved |
| **Analyst** | Mohamed Fadhih |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Tactic** | Credential Access |
| **Detection Rule** | rule1-brute-force.kql |

---

## 1. Preparation

- **Detection tool:** Microsoft Sentinel — Scheduled Analytics Rule
- **Log source:** Windows Security Event Log (EventID 4625)
- **Data connector:** Windows Security Events via AMA
- **Workspace:** law-soc-lab (Azure Australia Southeast)
- **Alert threshold:** 5+ failed logins within 5 minutes from same source

---

## 2. Identification

**Alert triggered:** 20 × EventID 4625 (Failed Logon) detected within a 5-minute window

**Evidence:**
- Target accounts: fakeuser1 through fakeuser10
- Workstation: vm-windows-target
- All attempts originated from the same internal source
- Pattern consistent with automated credential stuffing attack

**KQL query used for investigation:**
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count(), AccountNames = make_set(TargetUserName)
  by WorkstationName, IpAddress
| where FailedAttempts >= 5
```

**Scope assessment:** Single workstation affected. No successful logon (EventID 4624) observed from the same source immediately after the failed attempts. No lateral movement detected.

---

## 3. Containment

**Immediate actions recommended:**
- Block source IP at Network Security Group (NSG) level
- Enable account lockout policy (threshold: 5 attempts, 30-minute lockout)
- Disable RDP public exposure — use Azure Bastion instead

**Escalation decision:** In a production environment, this would be escalated to Tier 2 for root cause analysis and threat actor attribution.

---

## 4. Eradication

- No malware or persistence mechanisms identified
- Confirmed no new accounts created (EventID 4720 not triggered)
- Confirmed no privilege escalation (EventID 4672 not triggered)
- Confirmed no successful authentication from attacker source

---

## 5. Recovery

- Verify account lockout policies are enforced across all systems
- Reset passwords for any targeted accounts as precaution
- Monitor for 24 hours for repeat attempts from same or similar sources
- Review NSG rules to restrict RDP access to known IP ranges only

---

## 6. Lessons Learned

- Alert threshold of 5 attempts generated zero false positives during 1-hour observation period
- Recommend adding geolocation enrichment to alert for production use
- Consider implementing Azure AD Identity Protection for cloud account monitoring
- RDP should not be exposed directly to internet — implement JIT access or Azure Bastion

---

## Timeline

| Time | Event |
|------|-------|
| T+0:00 | First failed login attempt detected |
| T+0:02 | 5th failed attempt — alert threshold triggered |
| T+0:05 | Sentinel alert fired — analyst notified |
| T+0:10 | Scope assessment complete — single host, no lateral movement |
| T+0:20 | Containment recommendation issued |
| T+0:30 | Incident closed — no breach confirmed |
