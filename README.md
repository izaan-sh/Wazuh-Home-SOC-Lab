# 🛡️ Home SOC Lab: Security Monitoring, Detection Engineering & Active Response

**Platform:** Wazuh SIEM/XDR  
**Author:** Izaan Shumaiz | Cybersecurity & AI Graduate  
**Build Period:** September 15–17, 2026 | **Report Date:** September 20, 2026  


![Wazuh](https://img.shields.io/badge/Wazuh-00A9E0?style=for-the-badge&logo=wazuh&logoColor=white)
![SIEM](https://img.shields.io/badge/Security-SIEM%20%26%20XDR-000000?style=for-the-badge&logo=shield&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)



![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Kusto_Query_Language-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![SIEM](https://img.shields.io/badge/Cloud_SIEM-SOAR-000000?style=for-the-badge&logo=shield&logoColor=white)
![Log Analytics](https://img.shields.io/badge/Log_Analytics-Workspace-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)


---

## 📌 Executive Summary

This project documents the design, deployment, and practical validation of a home Security Operations Center (SOC) lab built on **Wazuh** (v4.14.7). The project extends beyond standard setup to demonstrate end-to-end security operations across heterogeneous endpoints (Windows and Ubuntu Linux). Key achievements include:

- Enrolling and monitoring heterogeneous agents.
- Extending Windows telemetry with **Sysmon**.
- Developing original correlation rules mapped to the **MITRE ATT&CK** framework.
- Configuring automated **Active Response** for SSH brute-force mitigation.
- Building a customized operational SOC dashboard.
- Validating the complete **Detect → Respond → Recover** lifecycle through hands-on attack simulations.

---

## 📐 Architecture & Environment

The lab runs inside an isolated virtual network hosted on **Oracle VirtualBox**.

| Resource | Role / Specifications | IP Address / Details |
| :--- | :--- | :--- |
| **Hypervisor** | Oracle VirtualBox (32 GB RAM Host) | Isolated Segment: `192.168.68.0/24` |
| **SIEM / XDR** | **Wazuh v4.14.7** Manager (`node01`) | Central log collector, correlator, and alert engine |
| **Agent 001** | `IZAAN-Windows` (Windows 10 Pro) | `192.168.68.131` (2 vCPU / 4 GB RAM + Sysmon) |
| **Agent 002** | `IZAAN-Linux` (Ubuntu 24.04.5 LTS) | `192.168.68.130` (Exposed SSH target) |

<p align="center">
  <img width="1918" height="1006" alt="Screenshot 2026-09-21 121809" src="https://github.com/user-attachments/assets/0d163cb8-921d-458f-8ab1-72fa4aa058ea" />
  <br><em>Figure 3.1 — Wazuh Manager displaying active Agent 001 (Windows) and Agent 002 (Linux).</em>
</p>

---

## 🚀 Implementation Phases

### Phase 1 & 2: Infrastructure Deployment & Telemetry Enrichment
- Deployed a single-node **Wazuh Manager** (`node01`) for central indexing and correlation.
- Enrolled `IZAAN-Windows` and `IZAAN-Linux` endpoints.
- Deployed **Sysmon** on `IZAAN-Windows` to capture advanced process creation, network connection, and file system events beyond standard Windows Event Logs.

<p align="center">
  <img width="1919" height="1002" alt="Screenshot 2026-09-21 121857" src="https://github.com/user-attachments/assets/23617a7c-550f-4ecd-a9a2-9065788ba4bb" />
  <br><em>Figure 4.1 — IZAAN-Windows inventory and MITRE ATT&CK tactics breakdown derived from Sysmon events.</em>
</p>

---

### Phase 3: Telemetry Ingestion & Threat Hunting
To verify log ingestion before engineering custom detections, baseline activity was generated across both hosts. Over the review window, the Windows endpoint logged over **22,000 total events**, including **49 high-severity alerts (Level 12+)**.

<p align="center">
  <img width="1913" height="932" alt="Screenshot 2026-09-21 163140" src="https://github.com/user-attachments/assets/65da16ac-6f98-4e71-b359-9b7043adfcdc" />
  <br><em>Figure 4.2 — Threat Hunting view showing 22,028 total events and high-severity alert distributions.</em>
</p>

<p align="center">
  <img width="1917" height="472" alt="Screenshot 2026-09-21 163203" src="https://github.com/user-attachments/assets/0608dc85-b1d1-48a6-94a4-84e9bfa390d2" />
  <br><em>Figure 4.3 — Top alert types, rule groups, and PCI DSS requirement mapping.</em>
</p>

---

### Phase 4: Operational SOC Dashboard
Built a custom Wazuh dashboard consolidating key operational metrics into a single view:
1. **Failed Windows Logons**
2. **Linux SSH Authentication Activity by Source IP**
3. **Windows Account Change Trends**
4. **Total User Account Modifications**

<p align="center">
  <img width="1906" height="846" alt="Screenshot 2026-09-21 162518" src="https://github.com/user-attachments/assets/3f8cb67a-a621-41d3-805e-7c9ad4133374" />
  <br><em>Figure 4.4 — Custom SOC dashboard tracking authentication metrics and account changes.</em>
</p>

---

### Phase 5: File Integrity Monitoring (FIM) & Custom Detections

#### 1. File Integrity Monitoring (`syscheck`)
Configured `syscheck` on a monitored path to track file modifications. Validation confirmed accurate categorization for file creation (`added`), modification (`modified`), and deletion (`deleted`).

<p align="center">
  <img width="1919" height="1004" alt="Screenshot 2026-09-21 161756" src="https://github.com/user-attachments/assets/0140f9ed-c68d-4f14-859d-b0bd9e4a052f" />
  <br><em>Figure 4.5 — FIM log table displaying file operations classified by rule ID.</em>
</p>

#### 2. Custom Detection Rules (`local_rules.xml`)
Authored two original detection rules mapped directly to MITRE ATT&CK techniques:

* **Rule 100200 (Level 12) — Guest Account Enabled**
  * **MITRE ATT&CK:** [T1078 (Valid Accounts)](https://attack.mitre.org/techniques/T1078/)
  * **Trigger:** Triggers when Windows Event ID `4722` targets the built-in "Guest" account.

<p align="center">
  <img width="1877" height="816" alt="Screenshot 2026-09-21 161131" src="https://github.com/user-attachments/assets/8ca463ed-0b01-40bc-82b5-85af4be9f914" />
  <br><em>Figure 4.6 — Rule 100200 configuration in local_rules.xml.</em>
</p>

<p align="center">
  <img width="1465" height="529" alt="Screenshot 2026-09-21 162718" src="https://github.com/user-attachments/assets/08604e6a-69f8-43fb-9aa3-194e0609e096" />
  <br><em>Figure 4.7 — Alert generated when user "Bob" enabled the Guest account on IZAAN-Windows.</em>
</p>

* **Rule 100101 (Level 10) — SSH Brute-Force Threshold**
  * **MITRE ATT&CK:** [T1110 (Brute Force)](https://attack.mitre.org/techniques/T1110/)
  * **Trigger:** Triggers upon **3 failed SSH logins** from the same source IP within **120 seconds**.

<p align="center">
  <img width="1873" height="816" alt="Screenshot 2026-09-21 161208" src="https://github.com/user-attachments/assets/75c2a521-0b66-4074-9dba-bbcb7ad9c2d0" />
  <br><em>Figure 4.8 — Rule 100101 configuration for frequency-based detection in local_rules.xml.</em>
</p>

<p align="center">
  <img width="1468" height="445" alt="Screenshot 2026-09-21 165408" src="https://github.com/user-attachments/assets/b71a07c7-b1fb-448a-9412-f60200adfd11" />
  <br><em>Figure 4.9 — Alert generated following repeated failed SSH attempts against IZAAN-Linux.</em>
</p>

---

### Phase 6: Automated Active Response

Configured Wazuh's **Active Response** mechanism to bind Rule `100101` to a `firewall-drop` action, executing `iptables` rules on `IZAAN-Linux` to automatically block the attacker's IP.

<p align="center">
  <img width="1475" height="512" alt="Screenshot 2026-09-21 162957" src="https://github.com/user-attachments/assets/9c7c8990-d989-45e0-b255-10460c68f3a0" />
  <br><em>Figure 4.10 — Active Response execution log confirming source IP addition to iptables.</em>
</p>

---

## 🧪 Attack Simulation & Validation Matrix

Every detection and response capability was manually tested and validated:

| Scenario | Attack Trigger | Expected Detection | Observed Result & Containment Verification |
| :--- | :--- | :--- | :--- |
| **SSH Brute Force** | Repeated failed SSH logons from target IP | **Rule 100101** (T1110) | Alert generated; Active Response automatically appended the source IP to `iptables`. |
| **Containment Verification** | ICMP `ping` + SSH login attempt from blocked IP | Traffic drop via `firewall-drop` | `ping` returned *Connection Timed Out*; SSH returned *Permission Denied*. |
| **Recovery** | Manual removal of IP from `iptables` | Network restoration | ICMP connectivity and SSH access fully restored. |
| **Guest Account Enabled** | Enabled native Guest account on Windows host | **Rule 100200** (T1078) | Alert generated capturing actor (`Bob`) and target (`Guest`). |
| **File Tampering** | File creation, modification, and deletion in watched directory | `syscheck` FIM rules | All 3 event types (`added`, `modified`, `deleted`) accurately categorized. |

---

## 🧰 Skills & Technologies Demonstrated

- **SIEM / XDR Administration:** Wazuh Manager deployment, agent enrollment, and XML-based rule tuning.
- **Telemetry & Logging:** Sysmon XML deployment for process and network visibility on Windows endpoints.
- **Detection Engineering:** Rule creation with custom frequency, level, and timeframe parameters mapped to MITRE ATT&CK techniques.
- **SOAR / Automated Response:** Configuration of host-based `iptables` Active Response scripts for real-time containment.
- **Threat Hunting & Dashboards:** Custom dashboard creation and log analysis.
- **Virtual Network Isolation:** Host-only virtual networking inside Oracle VirtualBox.

---

## 🎯 Next Steps & Future Enhancements

- [ ] Integrate **Atomic Red Team** scripts to test additional MITRE ATT&CK techniques.
- [ ] Connect a dedicated case management platform like **Shuffle SOAR** or **TheHive**.
- [ ] Incorporate network-level IDS telemetry using **Suricata** or **Zeek**.
