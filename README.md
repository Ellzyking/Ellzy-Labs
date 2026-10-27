# Hi, I'm Elliot! 👋

### **Cybersecurity Analyst | SOC | Detection Engineering | SIEM & Network Security**

Welcome to my cybersecurity portfolio! I specialize in Active Directory security, SIEM detection engineering, and adversary emulation. Below you will find my hands-on laboratory environments, custom detection rules, and verified security architecture projects.

---

## 🛡️ Cybersecurity Projects

### 🔹 [Project 2: Purple Team Operations – Active Directory Threat Simulation & Remediation](./Active-Directory-Threat-Detection/README.md)
* **Architecture:** Windows Server 2019 (DC01), Windows 11 Enterprise, Ubuntu Linux (Wazuh v4.14.1), Microsoft Sysmon.
* **Emulation (Red):** Executed Kerberoasting (T1558.003) via Rubeus and LSASS credential dumping (T1003.001) using native LOLBins via Atomic Red Team.
* **Detection (Blue):** Engineered custom Level 12 Wazuh rules (PCRE2 regex) targeting RC4 ticket encryption (0x17) and Sysmon Event ID 10 process access. Translated detection logic to vendor-neutral Sigma rules.
* **Remediation & Purple Teaming:** Disabled legacy RC4 Kerberos encryption domain-wide via Group Policy and enforced Windows Defender Attack Surface Reduction (ASR) rules. Verified complete neutralization through iterative re-testing.

### 🔹 [Project 1: Windows Brute-Force Detection & Telemetry Analysis](./Window-Brute-Force/README.md)
* Telemetry ingestion, authentication failure analysis, and baseline monitoring for Windows endpoint environments.

---

## 📜 Certifications & Studies
* **CompTIA Security+** (In Progress / Preparing)
* **Active Directory Security & Detection Engineering** (Hands-on Lab Specialization)

---

## 🌐 Connect With Me
* **GitHub:** [github.com/Ellzyking](https://github.com/Ellzyking)
* **LinkedIn:** *[Add your LinkedIn profile URL here]*







