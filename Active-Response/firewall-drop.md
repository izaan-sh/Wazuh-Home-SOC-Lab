# ⚡ Active Response Configuration: Automatic Firewall Drop

**Target Host:** `IZAAN-Linux` (Ubuntu 24.04.5 LTS)  
**Triggering Rule:** Rule `100101` (SSH Brute Force Detected — MITRE T1110)  
**Action:** Automatically appends offending source IP address to `iptables` / `firewalld` deny rules.

---

## 📌 Overview

Wazuh's Active Response framework executes automated scripts on monitored endpoints when specific security alerts trigger. In this lab, Active Response was configured to turn detection into active containment by automatically dropping network traffic from an IP address that attempts an SSH brute-force attack.

---

## ⚙️ Configuration Setup

### 1. Command Definition (`ossec.conf` on Wazuh Manager)
Defines the executable script to run when triggered. The built-in `firewall-drop` script is used to block network traffic at the host firewall level.

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>