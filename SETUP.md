# 🔧 Multi-SIEM SOC Lab - Complete Setup Guide

![Setup](https://img.shields.io/badge/Setup%20Time-8--10%20Hours-blue)
![VMs](https://img.shields.io/badge/VMs-5-green)
![SIEMs](https://img.shields.io/badge/SIEMs-4-orange)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow)

> **Estimated Time:** 8-10 hours (split across 3-4 days)

---

## 📋 Table of Contents

- [Phase 1: Environment Preparation](#phase-1)
- [Phase 2: Deploy Ubuntu VMs](#phase-2)
- [Phase 3: Deploy Windows Target VM](#phase-3)
- [Phase 4: Install Splunk](#phase-4)
- [Phase 5: Setup Microsoft Sentinel](#phase-5)
- [Phase 6: Install Wazuh](#phase-6)
- [Phase 7: Install ELK Stack](#phase-7)
- [Phase 8: Install Sysmon](#phase-8)
- [Phase 9: Jira Cloud Integration](#phase-9)
- [Phase 10: Verification](#phase-10)

---

## 📋 Phase 1: Environment Preparation (Day 1) <a name="phase-1"></a>

### 1.1 Download Required Software

| Software | Version | Size | Download |
|----------|---------|------|----------|
| Ubuntu Server | 22.04 LTS | ~1.5GB | [Download](https://ubuntu.com/download/server) |
| Windows 10 | Pro 22H2 | ~5GB | [Download](https://www.microsoft.com/software-download/windows10) |
| VirtualBox | Latest | ~100MB | [Download](https://www.virtualbox.org/wiki/Downloads) |
| Sysmon | 15.x | ~4MB | [Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |

### 1.2 Create Virtual Network

**VirtualBox:**
```
File → Host Network Manager → Create new adapter
IPv4: 192.168.56.1
Mask: 255.255.255.0
DHCP: Disabled
```

**VMware:**
```
Edit → Virtual Network Editor → Add Network (VMnet8)
Subnet: 192.168.56.0/24
DHCP: Disabled
```

---

## 🐧 Phase 2: Deploy Ubuntu VMs (Day 1-2) <a name="phase-2"></a>

### 2.1 Create Splunk VM

**VM Settings:**
| Setting | Value |
|---------|-------|
| Name | Splunk-SIEM |
| OS | Ubuntu 22.04 64-bit |
| RAM | 4GB |
| CPU | 2 cores |
| Disk | 50GB |
| Network | Host-Only (192.168.56.101) |

**Post-install static IP:**
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
network:
  ethernets:
    enp0s8:
      addresses: [192.168.56.101/24]
      nameservers:
        addresses: [8.8.8.8]
  version: 2
```
```bash
sudo netplan apply
```

### 2.2 Clone for Other SIEMs

```
Splunk VM → Clone → 3 times:
├── Sentinel-Agent  → 192.168.56.102
├── Wazuh-Manager   → 192.168.56.103
└── ELK-Stack       → 192.168.56.104
```

After each clone, update IP in netplan and run `sudo netplan apply`.

---

## 🪟 Phase 3: Deploy Windows Target VM (Day 2) <a name="phase-3"></a>

### 3.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | Windows-Target |
| OS | Windows 10 64-bit |
| RAM | 4GB |
| CPU | 2 cores |
| Disk | 60GB |
| Network | Host-Only |

### 3.2 Post-Installation Setup

```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.105 -PrefixLength 24

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Disable Windows Defender (Lab only!)
Set-MpPreference -DisableRealtimeMonitoring $true

# Create test users for attack simulations
net user testuser Password123! /add
net user admin2 Admin@2024 /add
net localgroup Administrators admin2 /add
```

---

## 🔥 Phase 4: Install Splunk (Day 2) <a name="phase-4"></a>

### 4.1 Install Splunk Enterprise

```bash
# On Splunk VM (192.168.56.101)
cd /tmp
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6b9c8185839-Linux-x86_64.tgz'
sudo tar xvzf splunk.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd admin123

# Enable boot start
sudo /opt/splunk/bin/splunk enable boot-start

# Open firewall
sudo ufw allow 8000/tcp
sudo ufw allow 9997/tcp
sudo ufw enable
```

**Access:** `http://192.168.56.101:8000` | admin / admin123

### 4.2 Install Splunk Universal Forwarder on Windows

```powershell
# Download from https://www.splunk.com/en_us/download/universal-forwarder.html
msiexec.exe /i splunkforwarder-9.1.2-x64-release.msi `
  RECEIVING_INDEXER="192.168.56.101:9997" `
  AGREETOLICENSE=Yes /quiet
```

**Configure inputs.conf:**
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```
```ini
[WinEventLog://Security]
disabled = 0
index = windows

[WinEventLog://System]
disabled = 0
index = windows

[WinEventLog://Application]
disabled = 0
index = windows

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

```powershell
Restart-Service SplunkForwarder
```

---

## ☁️ Phase 5: Setup Microsoft Sentinel (Day 3) <a name="phase-5"></a>

### 5.1 Create Azure Resources

```
1. portal.azure.com → Create Resource Group: SOC-Lab-RG
2. Create Log Analytics Workspace: SOCLabWorkspace (East US)
3. Search "Microsoft Sentinel" → Add → Select SOCLabWorkspace
```

### 5.2 Connect Windows VM to Sentinel

```powershell
# On Windows Target
Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile AzureConnectedMachineAgent.msi
msiexec /i AzureConnectedMachineAgent.msi /quiet

# Connect (get exact command from Azure Portal)
azcmagent connect --resource-group "SOC-Lab-RG" --tenant-id "<tenant-id>" --location "eastus" --subscription-id "<sub-id>"
```

### 5.3 Configure Data Collection Rules

```
Sentinel → Configuration → Data Connectors
→ Windows Security Events via AMA
→ Create DCR: Windows-Security-Events-DCR
→ Resources: Windows-Target VM
→ Collect: All Security Events
```

---

## 🛡️ Phase 6: Install Wazuh (Day 3) <a name="phase-6"></a>

### 6.1 Install Wazuh Manager

```bash
# On Wazuh VM (192.168.56.103)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
# Save credentials from output!
```

**Access:** `https://192.168.56.103` | admin / [generated password]

### 6.2 Install Wazuh Agent on Windows

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.56.103" WAZUH_AGENT_NAME="Windows-Target"
NET START WazuhSvc
```

---

## 📊 Phase 7: Install ELK Stack (Day 3-4) <a name="phase-7"></a>

### 7.1 Install Elasticsearch

```bash
# On ELK VM (192.168.56.104)
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install elasticsearch -y
```

**Configure `/etc/elasticsearch/elasticsearch.yml`:**
```yaml
network.host: 192.168.56.104
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false  # Lab only!
```

```bash
sudo systemctl enable --now elasticsearch
curl http://192.168.56.104:9200  # Verify
```

### 7.2 Install Kibana

```bash
sudo apt-get install kibana -y
```

**Configure `/etc/kibana/kibana.yml`:**
```yaml
server.host: "192.168.56.104"
server.port: 5601
elasticsearch.hosts: ["http://192.168.56.104:9200"]
```

```bash
sudo systemctl enable --now kibana
```
**Access:** `http://192.168.56.104:5601`

### 7.3 Install Logstash

```bash
sudo apt-get install logstash -y
sudo nano /etc/logstash/conf.d/windows-logs.conf
```

```ruby
input {
  beats { port => 5044 }
}
filter {
  if [winlog][event_id] {
    mutate { add_field => { "event_type" => "windows" } }
  }
}
output {
  elasticsearch {
    hosts => ["http://192.168.56.104:9200"]
    index => "windows-logs-%{+YYYY.MM.dd}"
  }
}
```

```bash
sudo systemctl enable --now logstash
```

### 7.4 Install Winlogbeat on Windows

```powershell
Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip -OutFile winlogbeat.zip
Expand-Archive winlogbeat.zip -DestinationPath C:\ProgramData\
cd C:\ProgramData\winlogbeat-8.11.0-windows-x86_64
```

**Update winlogbeat.yml:**
```yaml
output.logstash:
  hosts: ["192.168.56.104:5044"]

winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application
  - name: Microsoft-Windows-Sysmon/Operational
```

```powershell
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

---

## 🔍 Phase 8: Install Sysmon (Day 4) <a name="phase-8"></a>

### 8.1 Install Sysmon on Windows

```powershell
# Download SwiftOnSecurity config (best practice)
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

# Install with config
cd C:\Users\cccos\Downloads\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify
sc query sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### 8.2 Add Sysmon to Splunk Forwarder

```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe add monitor "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" -index sysmon -sourcetype XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
.\splunk.exe restart
```

---

## 🎫 Phase 9: Jira Cloud Integration (Day 4) <a name="phase-9"></a>

### 9.1 Setup Jira Cloud Account

```
1. Go to https://atlassian.net → Sign up (free)
2. Create project:
   - Type: Scrum / Kanban
   - Name: SOC Incident Response Lab
   - Key: KAN
3. Note your domain: yourname.atlassian.net
```

### 9.2 Generate Jira API Token

```
1. https://id.atlassian.com/manage-profile/security/api-tokens
2. Create API Token → Name: Splunk-Integration
3. Copy token (save it — shown only once!)
```

### 9.3 Verify Jira Priorities

```
Jira Settings (⚙️) → Work Items → Priorities
Confirm these exist (case-sensitive!):
├── Highest
├── High
├── Medium
├── Low     ← Must be capital L
└── Lowest
```

> ⚠️ **Important:** Splunk sends priority values exactly as typed. `low` ≠ `Low` — Jira will reject it!

### 9.4 Install Splunk Add-on for Jira Cloud

```
Splunk Web → Apps → Find More Apps
Search: "Jira Cloud"
Install: Splunk Add-on for Jira Cloud
Restart Splunk when prompted
```

### 9.5 Configure Jira Account in Splunk

```
Splunk Web → Apps → Jira Cloud → Configuration → Account
Click "Add"
Fill:
  - Account Name: JiraSOCLab
  - Jira URL: https://yourname.atlassian.net
  - Username: your-email@gmail.com
  - API Token: [paste token from 9.2]
Save
```

### 9.6 Create Alert with Jira Action

```
Splunk → Alerts → New Alert
- Name: SOC Incident Auto-Ticket
- Alert Type: Scheduled / Real-time
- Add Alert Action → Jira Cloud Issue
  - Project: KAN
  - Issue Type: Task / Bug
  - Summary: Splunk Alert: $name$
  - Priority: Low   ← Capital L!
  - Description: Alert triggered at $trigger_time$
Save
```

### 9.7 Verify Integration

```bash
# On Splunk VM — watch logs
sudo tail -f "/opt/splunk/var/log/splunk/splunk_ta_jira_cloud_alert_action_*.log"

# Success message to look for:
# Successfully created Jira Issue: https://yourname.atlassian.net/browse/KAN-X
```

**Check Jira board:** `https://yourname.atlassian.net/jira/software/projects/KAN/boards`

---

## ✅ Phase 10: Verification (Day 4) <a name="phase-10"></a>

### 10.1 Test Log Flow — All SIEMs

```powershell
# On Windows Target — Generate test events
net user testlog Password123! /add
net user testlog /delete
```

**Verify in each SIEM:**

**Splunk (SPL):**
```spl
index=windows EventCode=4720 OR EventCode=4726
| table _time, EventCode, Account_Name
```

**Sentinel (KQL):**
```kql
SecurityEvent
| where EventID in (4720, 4726)
| project TimeGenerated, EventID, Account
```

**Wazuh:**
```
Security Events → Windows → Filter: Event ID 4720 / 4726
```

**ELK (Kibana):**
```
Index: windows-logs-*
Filter: winlog.event_id: 4720
```

### 10.2 Final Checklist

| Component | Check | Status |
|-----------|-------|--------|
| Splunk Enterprise | `http://192.168.56.101:8000` | ✅ |
| Wazuh Dashboard | `https://192.168.56.103` | ✅ |
| ELK Kibana | `http://192.168.56.104:5601` | ✅ |
| Microsoft Sentinel | Azure Portal | ✅ |
| Sysmon on Windows | `sc query sysmon64` | ✅ |
| UF Sending Logs | SPL: `index=windows \| head 5` | ✅ |
| Jira Auto-Tickets | Check KAN board | ✅ |

---

## 🎉 Setup Complete!

You now have a **fully operational Multi-SIEM SOC Lab** with:

- ✅ 5 VMs running
- ✅ 4 SIEM platforms configured
- ✅ Logs flowing from Windows to all SIEMs
- ✅ Sysmon installed for deep visibility
- ✅ Jira Cloud auto-ticketing on Splunk alerts

**Next Step → [ATTACKS-AND-FINDINGS.md](./ATTACKS-AND-FINDINGS.md)** 🚀
