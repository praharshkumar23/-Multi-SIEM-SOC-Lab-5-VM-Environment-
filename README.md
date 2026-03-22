# 🛡️ Multi-SIEM SOC Lab (5-VM Environment)

![SOC Lab](https://img.shields.io/badge/Status-Active-brightgreen)
![SIEM](https://img.shields.io/badge/SIEMs-4%20Platforms-blue)
![Attacks](https://img.shields.io/badge/Attacks%20Simulated-30%2B-red)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange)

---

## 🎯 Project Overview

A production-grade **Security Operations Center (SOC) simulation lab** comparing detection capabilities across **4 major SIEM platforms**: Splunk, Microsoft Sentinel, Wazuh, and ELK Stack — with full **Jira Cloud ticketing automation**.

Simulated **30+ real-world attack scenarios** to identify detection gaps, practice cross-correlation, and demonstrate behavioral analysis over signature-based detection.

---

## 🔍 Why This Project?

### Problem
Different SIEM platforms detect threats differently. A single SIEM might miss critical attacks that another platform catches. Also, real SOC teams don't just detect — they **respond and track** using ticketing systems.

### Solution
This lab answers:
- ✅ Which SIEM detects specific attack types best?
- ✅ How to correlate events across multiple data sources?
- ✅ Why behavioral analysis beats signature-based detection?
- ✅ How to automate incident ticketing from SIEM alerts?

### Real Impact
- **18% more threats detected** using multi-SIEM correlation vs. single platform
- **47% of malware had 0/70 VirusTotal score** but showed behavioral IOCs
- **False positive reduction** through cross-platform context validation
- **Automated Jira ticket creation** on every Splunk alert trigger

---

## 🏗️ Lab Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Host Machine (VirtualBox)                    │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐      │
│  │ Splunk  │  │ Sentinel │  │ Wazuh  │  │   ELK     │      │
│  │ Ubuntu  │  │ Ubuntu   │  │ Ubuntu │  │  Ubuntu   │      │
│  │ 4GB RAM │  │ 4GB RAM  │  │ 4GB RAM│  │  4GB RAM  │      │
│  └────┬────┘  └─────┬────┘  └───┬────┘  └─────┬─────┘      │
│       │             │           │              │             │
│       └─────────────┴───────────┴──────────────┘            │
│                           │                                  │
│              ┌────────────▼───────────┐                      │
│              │     Windows 10 VM      │                      │
│              │    (Attack Target)     │                      │
│              │  Sysmon + UF Installed │                      │
│              └────────────────────────┘                      │
└──────────────────────────────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │ Jira Cloud  │
                    │  (Tickets)  │
                    └─────────────┘
```

---

## 📊 VM Specifications

| VM | OS | Purpose | Tool | RAM | Storage |
|----|----|---------|------|-----|---------|
| VM1 | Ubuntu 22.04 | Log aggregation + Ticketing | Splunk 9.x + Jira Integration | 4GB | 50GB |
| VM2 | Ubuntu 22.04 | Cloud SIEM | Microsoft Sentinel | 4GB | 50GB |
| VM3 | Ubuntu 22.04 | Open-source SIEM | Wazuh 4.x | 4GB | 50GB |
| VM4 | Ubuntu 22.04 | Log analytics | ELK Stack 8.x | 4GB | 50GB |
| VM5 | Windows 10 | Attack target | Sysmon 15 + UF | 4GB | 60GB |

**Total Resources:** 20GB RAM, 260GB Storage

---

## 🔗 Jira Cloud Integration (Splunk → Jira Automation)

### Overview
Splunk is integrated with **Jira Cloud** to automatically create incident tickets when security alerts are triggered — replicating real enterprise SOC workflows.

### How It Works
```
Splunk Alert Triggered
        ↓
Alert Action: Jira Cloud Issue
        ↓
Jira Ticket Auto-Created (SOC Incident Response Project)
        ↓
SOC Analyst Investigates via KAN Board
```

### Setup Steps
1. Install **Splunk Add-on for Jira Cloud** from Splunkbase
2. Configure API token in Jira Cloud account settings
3. Add Jira alert action in Splunk with project key + issue type
4. Set priority field exactly matching Jira priorities (case-sensitive!)

### Real Bug I Fixed 🐛
```
ERROR: Priority (low) is not present under the domain
```
**Root cause:** Splunk was sending `low` but Jira requires `Low` (capital L)  
**Fix:** Updated alert action priority field to match exact Jira priority name  
**Lesson:** Always verify exact field values in SIEM-to-ticketing integrations

### Tickets Created
| Ticket | Title | Status | Priority |
|--------|-------|--------|----------|
| KAN-4 | Connection Test - Splunk to Jira | Investigating | Low |
| KAN-5 | Connection Test - Splunk to Jira | Investigating | Low |
| KAN-6 | Connection Test - Splunk to Jira | Investigating | Low |

---

## 🧰 Prerequisites

### Hardware
- **Minimum:** 16GB RAM, 300GB free storage
- **Recommended:** 32GB RAM, 500GB SSD

### Software
- VirtualBox / VMware Workstation Pro
- Ubuntu 22.04 ISO
- Windows 10 ISO
- Microsoft Azure account (free tier)
- Splunk free trial / developer license
- Jira Cloud free account (atlassian.net)

### Knowledge
- Basic Linux command line
- Windows Event Logs fundamentals
- TCP/IP networking
- Log analysis concepts

---

## 🎯 What You'll Learn

### Technical Skills
- ✅ Deploy and configure 4 production SIEM platforms
- ✅ Forward logs from Windows to multiple SIEMs
- ✅ Write detection queries (SPL, KQL, Lucene)
- ✅ Simulate MITRE ATT&CK techniques
- ✅ Perform behavioral analysis
- ✅ Integrate SIEM with Jira for automated ticketing

### Investigation Skills
- ✅ Correlate events across multiple sources
- ✅ Reconstruct attack timelines
- ✅ Validate true vs false positives
- ✅ Extract IOCs from logs
- ✅ Map attacks to MITRE ATT&CK framework

### SOC Operations
- ✅ Alert triage across platforms
- ✅ Incident ticket management via Jira
- ✅ Incident documentation
- ✅ Cross-platform detection comparison

---

## 📂 Repository Structure

```
Multi-SIEM-SOC-Lab/
├── README.md
├── SETUP.md
├── ATTACKS-AND-FINDINGS.md
├── configs/
│   ├── splunk/
│   │   ├── inputs.conf
│   │   └── correlation-searches.spl
│   ├── sentinel/
│   │   └── analytics-rules.json
│   ├── wazuh/
│   │   └── ossec.conf
│   ├── elk/
│   │   └── logstash.conf
│   ├── jira/
│   │   └── alert-action-config.md
│   └── sysmon/
│       └── sysmonconfig.xml
├── scripts/
│   ├── brute-force-rdp.py
│   ├── mimikatz-runner.ps1
│   └── ioc-extractor.py
└── results/
    ├── detection-matrix.csv
    ├── screenshots/
    └── investigation-notes.md
```

---

## 📊 Key Results

### Detection Comparison (Top 5 Attacks)

| Attack Type | Splunk | Sentinel | Wazuh | ELK | Best SIEM |
|-------------|--------|----------|-------|-----|-----------|
| RDP Brute Force | ✅ Real-time | ✅ Real-time | ✅ Real-time | ⚠️ 1min delay | Splunk/Sentinel |
| PowerShell Obfuscation | ✅ Context-aware | ✅✅ Best context | ⚠️ Generic alert | ⚠️ Needs tuning | **Sentinel** |
| 0/70 VT Malware | ✅ Behavioral | ✅✅ Best correlation | ⚠️ Partial | ❌ Missed | **Sentinel** |
| Lateral Movement | ✅ Detected | ✅✅ Identity context | ✅ Detected | ⚠️ Manual work | **Sentinel** |
| Mimikatz (Memory) | ✅ Sysmon Event 10 | ✅ Sysmon Event 10 | ✅ Sysmon Event 10 | ✅ Sysmon Event 10 | Tied |

**🥇 Winner:** Microsoft Sentinel — best out-of-box behavioral correlation  
**🥈 Runner-up:** Splunk — best query flexibility + Jira automation  
**🏆 Best Open-Source:** Wazuh — real-time, easiest deployment  

---

## 🛠️ Tools Used

### SIEM Platforms
- Splunk Enterprise 9.x
- Microsoft Sentinel (Azure Log Analytics)
- Wazuh 4.x
- ELK Stack 8.x (Elasticsearch, Logstash, Kibana)

### Ticketing & Automation
- Jira Cloud (Atlassian)
- Splunk Add-on for Jira Cloud
- Automated alert-to-ticket pipeline

### Attack Tools
- Kali Linux (Hydra, Nmap, Metasploit)
- Atomic Red Team
- Mimikatz
- Empire C2 Framework

### Detection Enhancement
- Sysmon 15.0 (Enhanced Windows logging)
- Splunk Universal Forwarder
- VirusTotal API
- AbuseIPDB API
- MITRE ATT&CK Navigator

---

## 🚀 Quick Start

### Step 1: Setup Environment
Follow **[SETUP.md](./SETUP.md)** to:
1. Create 5 VMs
2. Install all 4 SIEM platforms
3. Configure log forwarding
4. Install Sysmon on Windows VM
5. Setup Jira Cloud integration

**Estimated time:** 8-10 hours

### Step 2: Run Attack Scenarios
Follow **[ATTACKS-AND-FINDINGS.md](./ATTACKS-AND-FINDINGS.md)** to:
1. Simulate 30+ attacks
2. Investigate in each SIEM
3. Compare detection capabilities
4. Document findings

**Estimated time:** 15-20 hours

---

## 🎓 For Your CV

> "Built production-grade 5-VM Multi-SIEM SOC Lab comparing Splunk, Microsoft Sentinel, Wazuh, and ELK Stack. Simulated 30+ MITRE ATT&CK techniques, identified 18% more threats through cross-SIEM correlation, and integrated Splunk with Jira Cloud for automated incident ticket creation."

---

## 📜 License
MIT License — Free to use for learning and portfolio purposes.
