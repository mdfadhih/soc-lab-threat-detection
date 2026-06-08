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
│  │ Server VM    │ ────────────► │ Workspace          │ │
│  │ (Attack      │  AMA Agent    │ (law-soc-lab)      │ │
│  │  Target)     │               └────────┬───────────┘ │
│  └──────────────┘                        │              │
│                                          │ Ingestion    │
│  Attacks Simulated:                      ▼              │
│  • Brute Force (T1110)        ┌────────────────────┐   │
│  • Scheduled Task (T1053)     │ Microsoft Sentinel │   │
│  • Account Enum (T1087)       │                    │   │
│  • PowerShell (T1059.001)     │ • 5 KQL Rules      │   │
│  • After-Hours Login (T1078)  │ • Incident Reports │   │
│                               │ • MITRE Mapping    │   │
│                               └────────────────────┘   │
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
| Target OS        | Windows Server 2022                   |
| Cloud            | Microsoft Azure (Australia Southeast) |

---

## MITRE ATT&CK Detection Coverage

| #   | Technique                    | TTP ID    | Detection Method             | EventID   | Severity |
| --- | ---------------------------- | --------- | ---------------------------- | --------- | -------- |
| 1   | Brute Force                  | T1110     | 5+ failed logins in 5 mins   | 4625      | High     |
| 2   | Scheduled Task Persistence   | T1053     | Suspicious task creation     | 4688/4698 | High     |
| 3   | Account Discovery            | T1087     | Enumeration command burst    | 4688      | Medium   |
| 4   | PowerShell Execution         | T1059.001 | Suspicious flags detected    | 4688      | High     |
| 5   | Valid Accounts (After Hours) | T1078     | RDP login outside 07-19 AEST | 4624      | Medium   |

---

## KQL Detection Rules

All 5 rules are saved in the `/kql-rules` folder. Each rule includes:

- Detection logic with comments
- MITRE TTP mapping
- Severity classification
- Tuning notes

### Rule 1 — Brute Force Detection

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

See `/kql-rules` folder for all 5 complete rules.

---

## Incident Reports

Three full NIST IR format reports documented in `/incident-reports`:

| Report | Incident                                | Severity | MITRE TTP |
| ------ | --------------------------------------- | -------- | --------- |
| IR-001 | Multiple Failed Authentication Attempts | High     | T1110     |
| IR-002 | Suspicious Scheduled Task Creation      | High     | T1053     |
| IR-003 | Suspicious PowerShell Execution         | High     | T1059.001 |

Each report covers: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned

---

## Lab Setup

### Prerequisites

- Azure free account (portal.azure.com)
- AWS free tier (optional — for CloudTrail/GuardDuty layer)
- GitHub account

### Step-by-step setup

1. Create Azure Resource Group (`rg-soc-lab`) in Australia Southeast
2. Deploy Log Analytics Workspace (`law-soc-lab`)
3. Enable Microsoft Sentinel on the workspace
4. Deploy Windows Server 2022 VM (`vm-windows-target`)
5. Create Data Collection Rule via Windows Security Events via AMA connector
6. Enable audit policies on VM via `auditpol` commands
7. Run attack simulations (see `/attack-scripts` folder)
8. Deploy KQL detection rules in Sentinel Analytics

---

## Key Findings

- **500+ security events** generated and analysed during lab operation
- **5 MITRE ATT&CK techniques** detected with custom KQL rules
- **0 false positives** after tuning brute force threshold to ≥5 attempts
- **EventID 4688** command line auditing enabled via registry — critical for PowerShell detection
- **Azure Monitor Agent (AMA)** used over legacy MMA agent per Microsoft recommendation
- **LogonType 3** identified as Azure VM network logon type (vs standard LogonType 10)

---

## Screenshots

All evidence screenshots in `/screenshots` folder:

| #   | Screenshot              | Description                       |
| --- | ----------------------- | --------------------------------- |
| 01  | Resource group created  | rg-soc-lab in Australia Southeast |
| 02  | Log Analytics workspace | law-soc-lab overview              |
| 03  | Sentinel enabled        | Overview dashboard                |
| 04  | VM running              | vm-windows-target status          |
| 05  | Agent connected         | 1 Windows computer connected      |
| 06  | Data connector          | Windows Security Events via AMA   |
| 07  | Logs flowing            | SecurityEvent table with results  |
| 08  | Brute force detected    | EventID 4625 x20 in Sentinel      |
| 09  | PowerShell detected     | EventID 4688 with CommandLine     |

---

## Analyst Notes

> This lab simulates a Tier 1 SOC analyst workflow — from environment setup through attack simulation, detection tuning, and incident documentation. All attacks were conducted in an isolated Azure lab environment against systems I own and control.

---

## About

**Mohamed Fadhih** — Cybersecurity Analyst | Melbourne, Australia

- Master of Cybersecurity — Monash University
- AWS Certified Cloud Practitioner
- Google Cybersecurity Professional Certificate
- SOC Operations Internship — Digillium (500+ alerts triaged)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/fadhih)
[![Portfolio](https://img.shields.io/badge/Portfolio-Visit-green)](http://my-portfolio-seven-tawny-79.vercel.app/)
