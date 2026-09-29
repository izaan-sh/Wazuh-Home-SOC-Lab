# Wazuh Home SOC Lab

### Security Monitoring, Detection Engineering & Active Response

A hands-on home Security Operations Center (SOC) lab built around **Wazuh** to practice endpoint monitoring, security telemetry collection, threat hunting, detection engineering, File Integrity Monitoring (FIM), and automated incident response.

The lab monitors both **Windows and Linux endpoints**, extends Windows visibility using **Sysmon**, includes custom detection rules mapped to **MITRE ATT&CK**, and uses Wazuh Active Response to automatically contain SSH brute-force activity.

> **Lab build:** September 15–17, 2026
> **Platform:** Wazuh 4.14.7
> **Environment:** Oracle VirtualBox
> **Focus:** SOC Operations / Blue Team / Detection Engineering

---

## 1. Project Overview

The objective of this project was to build a functional SOC environment rather than simply install a SIEM and collect logs.

The lab was designed to demonstrate the complete security monitoring lifecycle:

```text
Endpoint Activity
       ↓
Telemetry Collection
       ↓
Wazuh SIEM / XDR
       ↓
Detection Engineering
       ↓
Alert Investigation
       ↓
Automated Response
       ↓
Containment
       ↓
Recovery & Validation
```

The environment includes two monitored endpoints:

* **Windows 10 Pro** endpoint with Sysmon
* **Ubuntu Linux** endpoint with SSH exposed for controlled brute-force testing

The project also included:

* Custom Wazuh monitoring dashboard
* File Integrity Monitoring
* Custom XML detection rules
* MITRE ATT&CK mapping
* SSH brute-force detection
* Windows Guest account detection
* Automated firewall-based IP blocking
* Manual containment and recovery validation

Every major capability was tested using activity generated inside the lab rather than being considered complete based only on configuration.

---

# 2. Objectives

The main objectives of the lab were to:

* Deploy a functional Wazuh manager and enroll Windows and Linux endpoints.
* Extend Windows telemetry using Sysmon.
* Generate and review endpoint activity before creating custom detections.
* Build a centralized SOC monitoring dashboard.
* Configure File Integrity Monitoring.
* Develop custom Wazuh detection rules.
* Map detections to MITRE ATT&CK techniques.
* Configure automated Active Response.
* Validate the complete **detect → respond → recover** workflow.

---

# 3. Lab Architecture

The lab was built entirely within **Oracle VirtualBox** on a Windows host using an isolated virtual network.

```text
                         ┌──────────────────────┐
                         │    Wazuh Manager     │
                         │       node01         │
                         │     Wazuh 4.14.7     │
                         └──────────┬───────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     │                             │
              ┌──────▼───────┐             ┌──────▼───────┐
              │ Windows 10    │             │ Ubuntu Linux │
              │ IZAAN-Windows │             │ IZAAN-Linux  │
              │               │             │              │
              │ + Sysmon      │             │ + SSH        │
              └───────────────┘             └──────────────┘
```

### Environment

| Component          | Configuration      |
| ------------------ | ------------------ |
| Hypervisor         | Oracle VirtualBox  |
| Host               | Windows PC         |
| Host RAM           | 32 GB              |
| SIEM/XDR           | Wazuh 4.14.7       |
| Manager            | `node01`           |
| Network            | `192.168.68.0/24`  |
| Windows Agent      | `IZAAN-Windows`    |
| Windows IP         | `192.168.68.131`   |
| Windows Version    | Windows 10 Pro     |
| Windows Resources  | 2 vCPU / 4 GB RAM  |
| Windows Telemetry  | Sysmon             |
| Linux Agent        | `IZAAN-Linux`      |
| Linux IP           | `192.168.68.130`   |
| Linux Version      | Ubuntu 24.04.5 LTS |
| Linux Test Service | SSH                |

Both endpoints were successfully enrolled with the Wazuh manager and reported as active.

---

# 4. Phase 1 — Wazuh Manager Deployment

The first stage was deploying the Wazuh manager as the central SOC component.

The manager was responsible for:

* Endpoint log collection
* Event processing
* Alert generation
* Detection rule processing
* Correlation
* Centralized monitoring

The Wazuh manager acted as the central point of visibility for both endpoints.

### Evidence

![Wazuh Endpoints](screenshots/01-wazuh-endpoints.png)

---

# 5. Phase 2 — Endpoint Enrollment & Sysmon

Two heterogeneous endpoints were enrolled into the Wazuh manager:

### Windows

`IZAAN-Windows`

Windows 10 Pro was configured with **Sysmon** to provide additional endpoint telemetry.

Sysmon provided visibility into activity such as:

* Process creation
* Network connections
* File-related events

This extended the visibility available from native Windows Event Logs.

### Linux

`IZAAN-Linux`

The Ubuntu endpoint was enrolled for Linux security monitoring and used as the target for the controlled SSH brute-force simulation.

The resulting telemetry was visible within Wazuh's endpoint and MITRE ATT&CK views.

![Windows Agent Overview](screenshots/02-windows-agent-overview.png)

---

# 6. Phase 3 — Telemetry Generation & Threat Hunting

Before creating custom detections, activity was generated on both endpoints to verify that telemetry was reaching Wazuh correctly.

The Windows endpoint alone generated:

* **22,028 total events**
* **49 alerts at level 12 or above**
* **9 failed authentications**
* **6 successful authentications**

The events originated from multiple telemetry sources including:

* Sysmon
* Windows Security/Application logs
* Vulnerability Detection
* Security Configuration Assessment (SCA)

This confirmed that the telemetry pipeline was functioning before detection engineering was performed.

![Threat Hunting](screenshots/03-threat-hunting.png)

---

# 7. Phase 4 — Custom SOC Dashboard

A custom Wazuh dashboard was created to provide an operational overview of important security activity.

The dashboard focused on:

* Failed Windows logons
* Linux SSH authentication activity by source
* Windows account-change activity over time
* Total user-account modifications

This provided a centralized view for monitoring authentication and account activity without having to manually perform individual searches for each signal.

The dashboard recorded **74 user modifications** during the monitored period.

![Custom SOC Dashboard](screenshots/04-soc-dashboard.png)

---

# 8. Phase 5 — File Integrity Monitoring

Wazuh File Integrity Monitoring (`syscheck`) was enabled on a monitored directory.

The FIM functionality was validated by performing three types of file activity:

```text
Create File
    ↓
Modify File
    ↓
Delete File
```

Each action generated the expected event type:

* Added
* Modified
* Deleted

This confirmed that the monitored directory was being tracked correctly.

![File Integrity Monitoring](screenshots/05-fim-events.png)

---

# 9. Detection Engineering

One of the main goals of the project was to go beyond Wazuh's default ruleset.

Two custom detection rules were created in:

```text
local_rules.xml
```

The rules were designed around specific attack scenarios and mapped to MITRE ATT&CK techniques.

---

## 9.1 Rule 100101 — SSH Brute Force

### Objective

Detect repeated failed SSH authentication attempts originating from the same source IP.

### Detection Logic

```text
3 or more failed SSH authentications
            +
Same source IP
            +
Within 120 seconds
            ↓
       Rule 100101
```

### Configuration

| Attribute    | Value               |
| ------------ | ------------------- |
| Rule ID      | `100101`            |
| Level        | 10                  |
| Frequency    | 3                   |
| Timeframe    | 120 seconds         |
| Attack       | SSH Brute Force     |
| MITRE ATT&CK | T1110 — Brute Force |

The rule fires when three or more failed SSH authentication attempts occur from the same source IP within the configured timeframe.

### Rule Source

The rule source is available in:

```text
Rules/rule-100101-ssh-bruteforce.xml
```

![SSH Brute Force Rule](screenshots/08-ssh-bruteforce-rule.png)

### Validation

Repeated failed SSH authentication attempts were generated against the Ubuntu endpoint.

The custom rule successfully generated an alert once the configured threshold was reached.

![SSH Brute Force Alert](screenshots/09-ssh-bruteforce-alert.png)

---

# 10. Rule 100200 — Windows Guest Account Enabled

### Objective

Detect the enabling of the built-in Windows Guest account.

The detection uses Windows **Event ID 4722**, targeting the `Guest` account.

### Configuration

| Attribute        | Value                  |
| ---------------- | ---------------------- |
| Rule ID          | `100200`               |
| Level            | 12                     |
| Windows Event ID | `4722`                 |
| Target Account   | `Guest`                |
| MITRE ATT&CK     | T1078 — Valid Accounts |

The rule was designed to identify an account state change that could introduce an additional valid account into the Windows environment.

### Rule Source

```text
Rules/rule-100200-guest-account-enabled.xml
```

![Guest Account Rule](screenshots/06-guest-account-rule.png)

### Validation

The Guest account was enabled on the Windows endpoint.

Wazuh generated the expected alert and captured the relevant event context, including the source user and target account.

![Guest Account Alert](screenshots/07-guest-account-alert.png)

---

# 11. Phase 6 — Active Response

The SSH brute-force detection was extended beyond alert generation by configuring **Wazuh Active Response**.

The objective was to automatically contain the source IP after Rule `100101` fired.

### Response Workflow

```text
SSH Brute Force
       ↓
Rule 100101
       ↓
Wazuh Alert
       ↓
Active Response Triggered
       ↓
firewall-drop
       ↓
Source IP Added to iptables
       ↓
Traffic Blocked
```

The Active Response configuration used Wazuh's `firewall-drop` response to add the offending source IP to `iptables` on the Linux endpoint.

![Active Response](screenshots/10-active-response.png)

---

# 12. Attack Simulation & Validation

The lab was validated using controlled attack activity rather than relying only on configuration.

## Scenario 1 — SSH Brute Force

### Trigger

Repeated failed SSH logins from one source IP.

### Expected Detection

Rule `100101` fires.

### Observed Result

* Wazuh generated the alert.
* Active Response automatically blocked the source IP.
* The offending IP was added to `iptables`.

---

## Scenario 2 — Containment Validation

After the IP was blocked, connectivity was tested independently.

### Tests

```text
Ping → Target
SSH  → Target
```

### Result

```text
Ping
→ Connection timed out

SSH
→ Permission denied
```

This confirmed that the firewall response had actually taken effect rather than simply generating an Active Response event.

---

## Scenario 3 — Recovery

The blocked IP was manually removed from `iptables`.

Connectivity and login access returned to normal, completing the:

```text
Detect → Respond → Recover
```

cycle.

![Containment Validation](screenshots/11-containment-validation.png)

![Recovery Validation](screenshots/12-recovery-validation.png)

---

# 13. Validation Summary

| Scenario        | Trigger                          | Detection / Response          | Result                             |
| --------------- | -------------------------------- | ----------------------------- | ---------------------------------- |
| SSH Brute Force | Repeated failed SSH logins       | Rule 100101 + Active Response | Source IP automatically blocked    |
| Containment     | Ping + SSH against blocked IP    | `iptables` firewall drop      | Ping timed out and SSH was denied  |
| Recovery        | Remove blocked IP                | Manual `iptables` cleanup     | Connectivity restored              |
| Guest Account   | Guest account enabled            | Rule 100200                   | Alert generated with event context |
| File Tampering  | Create / modify / delete files   | Wazuh FIM                     | All three event types detected     |
| Account Changes | Windows user/group modifications | Custom dashboard              | 74 modifications tracked           |

---

# 14. Skills Demonstrated

### SIEM / XDR

* Wazuh manager deployment
* Agent enrollment
* Windows and Linux monitoring
* Wazuh ruleset customization
* Active Response configuration

### Endpoint Telemetry

* Sysmon deployment
* Windows endpoint monitoring
* Security event analysis
* Process and network telemetry

### Detection Engineering

* Custom XML detection rules
* Rule level tuning
* Frequency and timeframe configuration
* MITRE ATT&CK mapping
* Brute-force detection
* Account-state-change detection

### Incident Response

* Alert investigation
* Attack simulation
* Automated containment
* Firewall-based IP blocking
* Recovery validation

### Host & Network Security

* `iptables`
* Source IP blocking
* Automated firewall response
* Manual recovery and cleanup

### Monitoring & Threat Hunting

* Wazuh Threat Hunting
* Custom dashboards
* File Integrity Monitoring
* Authentication monitoring
* Account-change monitoring

### Virtualization

* Oracle VirtualBox
* Multi-VM isolated SOC environment
* Windows and Linux endpoint integration

These capabilities correspond to the skills and tooling documented in the project report.

---

# 15. Project Results

The completed lab demonstrated a functional security monitoring and response pipeline covering:

```text
                ┌─────────────────┐
                │ Endpoint Events │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Wazuh Telemetry │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Detection Rules │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Alert / Triage  │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Active Response │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │   Containment   │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │    Recovery     │
                └─────────────────┘
```

The project demonstrated that the detections and response mechanisms worked against generated activity rather than existing only as untested configurations.

The lab successfully combined:

* Endpoint telemetry
* SIEM monitoring
* Detection engineering
* MITRE ATT&CK mapping
* File Integrity Monitoring
* Threat hunting
* Automated containment
* Recovery validation

---

# 16. Repository Structure

```text
wazuh-home-soc-lab/
│
├── README.md
│
├── Rules/
│   ├── rule-100101-ssh-bruteforce.xml
│   └── rule-100200-guest-account-enabled.xml
│
├── Active-Response/
│   └── firewall-drop.md
│
└── screenshots/
    ├── 01-wazuh-endpoints.png
    ├── 02-windows-agent-overview.png
    ├── 03-threat-hunting.png
    ├── 04-soc-dashboard.png
    ├── 05-fim-events.png
    ├── 06-guest-account-rule.png
    ├── 07-guest-account-alert.png
    ├── 08-ssh-bruteforce-rule.png
    ├── 09-ssh-bruteforce-alert.png
    ├── 10-active-response.png
    ├── 11-containment-validation.png
    └── 12-recovery-validation.png
```

---

# 17. Future Improvements

The current lab provides a foundation that can be extended into a broader detection and response environment.

Potential future improvements include:

### Atomic Red Team

Introduce structured attack simulations using **Atomic Red Team** to test detection coverage against a broader range of MITRE ATT&CK techniques.

### SOAR Integration

Add a dedicated SOAR or case-management platform such as **TheHive** or **Shuffle** to extend the current Active Response workflow into broader incident orchestration and case management.

### Network Detection

Integrate a network-level IDS such as **Suricata** or **Zeek** alongside the existing host-based telemetry.

These extensions would allow the lab to move beyond individual detection scenarios toward broader attack simulation, network visibility, and incident orchestration.

---

# 18. Conclusion

This project resulted in a functional home SOC environment capable of monitoring Windows and Linux endpoints, collecting security telemetry, detecting suspicious activity, investigating alerts, and automatically responding to a confirmed brute-force scenario.

The main focus was not simply configuring Wazuh, but validating the entire security workflow through controlled activity:

**Detect → Investigate → Respond → Contain → Recover**

The project also provided practical experience with SIEM administration, endpoint telemetry, detection engineering, MITRE ATT&CK mapping, threat hunting, File Integrity Monitoring, firewall-based containment, and incident validation.

The custom detection rules and Active Response workflow demonstrate how a SIEM can be extended beyond default monitoring capabilities to support a more operational SOC workflow.
