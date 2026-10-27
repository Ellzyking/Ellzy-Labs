# Hi, I'm Elliot! 👋

### **Cybersecurity Analyst | SOC | Detection Engineering | SIEM & Network Security**

Welcome to my cybersecurity portfolio! I specialize in Active Directory security, SIEM detection engineering, and adversary emulation. Below you will find my hands-on laboratory environments, custom detection rules, and verified security architecture projects.

---

## 🛡️ Cybersecurity Projects

### 🔗 [Project 1: Windows Brute-Force Detection & Telemetry Analysis](Windows_Brute_Force_Folder_Name_Here)
* **Architecture:** Configured a local virtualized environment to simulate network authentication attacks against a Windows endpoint.
* **Log Ingestion:** Integrated Windows Security logs with Wazuh for centralized telemetry collection and parsing.
* **Detection Engineering:** Authored custom correlation rules in Wazuh and Sigma to detect high-volume failed network logons (Event ID 4625) originating from a single source.

### 🔗 Active-Directory-Threat-Detection
* **Architecture & Emulation:** Deployed a Windows Server 2019 Domain Controller and executed Kerberoasting (T1558.003) and LSASS credential dumping (T1003.001) using Atomic Red Team.
* **Detection (Blue):** Engineered custom Level 12 Wazuh rules targeting RC4 ticket encryption and Sysmon Event ID 10 process access, translating the logic into vendor-neutral Sigma rules.
* **Remediation & Purple Teaming:** Disabled legacy RC4 Kerberos encryption domain-wide via Group Policy and enforced Windows Defender ASR rules, verifying complete neutralization through iterative re-testing.

### 🔗 [Project 3: Suricata Network Intrusion Detection with Wazuh & Splunk](Network_Intrusion_Detection)
* **Network Visibility:** Deployed Suricata as an IDS to capture raw network flow telemetry and alert on volumetric reconnaissance (Nmap SYN scans).
* **Dual-SIEM Pipeline:** Ingested `eve.json` network logs into both Wazuh for signature-driven alerting and Splunk for statistical threat hunting.
* **Threat Hunting & Triage:** Authored SPL queries to extract anomalous process paths (`props.conf` XML parsing) and correlated network top-talkers with endpoint execution logs.

---

## 📜 Certifications & Studies
* **CompTIA Security+** (In Progress / Preparing)
* **Active Directory Security & Detection Engineering** (Hands-on Lab Specialization)

---

## 🌐 Connect With Me
* **GitHub:** [github.com/Ellzyking](https://github.com/Ellzyking)
* **LinkedIn:** *[Add your LinkedIn profile URL here]*







