# SOC Lab — Centralised Threat Detection & Incident Response

![Azure Sentinel](https://img.shields.io/badge/Azure-Sentinel-0078D4?style=flat&logo=microsoft-azure)
![KQL](https://img.shields.io/badge/KQL-5%20Detection%20Rules-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![NIST IR](https://img.shields.io/badge/NIST-Incident%20Response-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## Overview

A hands-on SOC detection lab built on Microsoft Azure — simulating real-world attack scenarios, writing custom KQL detection rules in Microsoft Sentinel, and documenting incidents using the NIST Incident Response framework.

Built to demonstrate Tier 1 SOC analyst skills relevant to the Australian cybersecurity market.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Azure (Australia Southeast)           │
│                                                         │
│  ┌──────────────┐    Security    ┌────────────────────┐ │
│  │ Windows      │    Events      │ Log Analytics      │ │
│  │ Server 2022  │ ────────────► │ Workspace          │ │
│  │ VM           │  AMA Agent    │ (law-soc-lab)      │ │
│  │ (Attack      │               └────────┬───────────┘ │
│  │  Target)     │                        │              │
│  └──────────────┘                        │ Ingestion    │
│                                          ▼              │
│  Attacks Simulated:          ┌────────────────────────┐ │
│  • Brute Force (T1110)       │   Microsoft Sentinel   │ │
│  • Process Enum (T1059)      │                        │ │
│  • Account Enum (T1087)      │  • 5 KQL Rules         │ │
│  • PowerShell (T1059.001)    │  • 3 Incident Reports  │ │
│  • After-Hours Login (T1078) │  • MITRE ATT&CK Map    │ │
│                              └────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## Tools & Technologies

| Category         | Tool                                  |
| ---------------- | ------------------------------------- |
| SIEM             | Microsoft Sentinel                    |
| Log Management   | Azure Log Analytics Workspace         |
| Query Language   | KQL (Kusto Query Language)            |
| Agent            | Azure Monitor Agent (AMA)             |
| Attack Framework | MITRE ATT&CK                          |
| IR Framework     | NIST SP 800-61                        |
| Target OS        | Windows Server 2022 Datacenter        |
| Cloud            | Microsoft Azure (Australia Southeast) |

---

## MITRE ATT&CK Detection Coverage

| #   | Technique                  | TTP ID    | Detection Method                             | EventID   | Severity |
| --- | -------------------------- | --------- | -------------------------------------------- | --------- | -------- |
| 1   | Brute Force                | T1110     | 5+ failed logins in 5 mins from same source  | 4625      | High     |
| 2   | Scheduled Task Persistence | T1053     | Suspicious task creation with PowerShell     | 4688/4698 | High     |
| 3   | Account Discovery          | T1087     | Enumeration command burst (net user, whoami) | 4688      | Medium   |
| 4   | PowerShell Execution       | T1059.001 | Bypass/hidden/IEX flags detected             | 4688      | High     |
| 5   | Valid Accounts After Hours | T1078     | RDP login outside 07:00–19:00 AEST           | 4624      | Medium   |

---

## KQL Detection Rules

All 5 rules saved in `/kql-rules` folder. Each includes detection logic, MITRE mapping, severity, and tuning notes.

### Rule 1 — Brute Force Detection (T1110)

```kql
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    AccountNames = make_set(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by WorkstationName, IpAddress
| where FailedAttempts >= 5
| extend MITRE_TTP = "T1110 - Brute Force", Severity = "High"
```

See `/kql-rules` folder for all 5 complete rules with full comments and tuning notes.

---

## Attack Simulations & Detections

### Attack 1 — Brute Force (T1110)

- **Method:** 10 failed login attempts against fakeuser1–fakeuser10
- **Detection:** 20 × EventID 4625 detected in Sentinel
- **Result:** KQL rule triggered — FailedAttempts: 20, AccountNames: [fakeuser1...fakeuser10]

### Attack 2 — Suspicious Process Creation (T1059)

- **Method:** Ran systeminfo, ipconfig, net.exe, cmd.exe from VM
- **Detection:** EventID 4688 — systeminfo.exe, cmd.exe, net.exe, ipconfig.exe captured
- **Result:** 20 process creation events detected with full command line logging

### Attack 3 — Account Enumeration (T1087)

- **Method:** Ran net user, net localgroup commands repeatedly
- **Detection:** EventID 4798/4799 — EnumCount: 9, EventIDs: [4799, 4798]
- **Result:** KQL rule triggered — MITRE_TTP: T1087, Severity: Medium

### Attack 4 — Suspicious PowerShell (T1059.001)

- **Method:** Ran powershell with -WindowStyle Hidden and -ExecutionPolicy bypass flags
- **Detection:** EventID 4688 — CommandLine captured with suspicious flags
- **Result:** KQL rule triggered — MITRE_TTP: T1059.001, Severity: High
- **Evidence:** Two detections — Hidden window + bypass execution policy

### Attack 5 — After Hours Login (T1078)

- **Method:** RDP login recorded during off-hours simulation
- **Detection:** EventID 4624 — LogonType 3, HourAEST: 15, IpAddress: 203.123.65.164
- **Result:** Login captured with AEST timezone calculation confirmed

---

## Incident Reports

Three full NIST IR format reports in `/incident-reports`:

| Report | Incident                                | Severity | MITRE TTP |
| ------ | --------------------------------------- | -------- | --------- |
| IR-001 | Multiple Failed Authentication Attempts | High     | T1110     |
| IR-002 | Suspicious Scheduled Task Creation      | High     | T1053     |
| IR-003 | Suspicious PowerShell Execution         | High     | T1059.001 |

Each report covers all 6 NIST phases:
Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned

---

## Screenshots Evidence

All screenshots in `/screenshots` folder:

### Setup & Configuration

| File                        | Description                                                                        |
| --------------------------- | ---------------------------------------------------------------------------------- |
| Resource_group_created.png  | rg-soc-lab resource group in Azure                                                 |
| Log_Analytics_workspace.png | law-soc-lab workspace list view                                                    |
| log_workplace_1.png         | law-soc-lab overview — Workspace ID, Status: Active, Location: Australia Southeast |
| Sentinel_enabled.png        | Microsoft Sentinel overview dashboard — Incidents(0) start state                   |
| VM_running.png              | vm-windows-target — Status: Running, Windows Server 2022, Australia Southeast      |
| Agent_connected.png         | law-soc-lab Agents — 1 Windows computer connected via AMA                          |
| Data_connector.png          | Windows Security Events via AMA — dcr-sentinel-security rule active                |
| Logs_flowing.png            | Sentinel Logs — SecurityEvent table showing 16 EventIDs across all attacks         |

### Attack Detections in Sentinel

| File                            | Description                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| Brute_force_detected.png        | Attack 1 — EventID 4625 x20, fakeuser1–fakeuser10, T1110 Brute Force, Severity: High  |
| ATTack-2.png                    | Attack 2 — EventID 4688, systeminfo.exe/cmd.exe/ipconfig.exe/net.exe detected         |
| AttacK_3.png                    | Attack 3 — EventID 4798/4799, EnumCount: 9, T1087 Account Discovery, Severity: Medium |
| Attack_4_1.png                  | Attack 4 — EventID 4688 PowerShell processes detected with CommandLine                |
| Attack_4_2.png                  | Attack 4 — PowerShell -WindowStyle Hidden detected, T1059.001, Severity: High         |
| Attack_4_3.png                  | Attack 4 — PowerShell -ExecutionPolicy bypass detected, T1059.001, Severity: High     |
| Attack_5.png                    | Attack 5 — EventID 4624, LogonType 3, HourAEST: 15, T1078 Valid Accounts              |
| Suspicious_process_creation.png | Process creation overview — all attack processes captured in Sentinel                 |

---

## Lab Setup Guide

### Prerequisites

- Azure free account — portal.azure.com ($200 credit, no charge for this lab)
- GitHub account for documentation

### Setup Steps

1. Create Resource Group `rg-soc-lab` — Australia Southeast
2. Deploy Log Analytics Workspace `law-soc-lab`
3. Enable Microsoft Sentinel on the workspace
4. Deploy Windows Server 2022 VM `vm-windows-target`
5. Connect via Windows Security Events via AMA data connector
6. Create DCR `dcr-sentinel-security` with AllEvents filter
7. Enable audit policies on VM:

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Task Scheduler" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
```

8. Enable command line logging:

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

9. Run attack simulations
10. Deploy KQL detection rules

---

## Key Findings & Observations

- **Security events generated and analysed across 5 simulations
- **5 MITRE ATT&CK techniques** successfully detected with custom KQL rules
- **EventID 4688 command line auditing** requires explicit registry key — not enabled by default
- **Azure Monitor Agent (AMA)** used over legacy MMA — per Microsoft recommendation
- **LogonType 3** confirmed as Azure VM network logon type — differs from standard RDP Type 10
- **Brute force threshold of 5** generated zero false positives during testing
- **Windows Security Events via AMA connector** required for correct SecurityEvent table population

---

## Analyst Notes

> All attacks conducted in an isolated Azure lab environment against systems I own and control. This lab simulates a real Tier 1 SOC analyst workflow — environment setup, attack simulation, alert detection, triage, and incident documentation.

---

## About

**Mohamed Fadhih** — Cybersecurity Analyst | Melbourne, Australia

- Master of Cybersecurity — Monash University (Group of Eight)
- AWS Certified Cloud Practitioner
- Google Cybersecurity Professional Certificate
- SOC Operations Intern — Digillium

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/fadhih)
[![Portfolio](https://img.shields.io/badge/Portfolio-Visit-green)](https://cybersecurity-portfolio-drab.vercel.app/)
