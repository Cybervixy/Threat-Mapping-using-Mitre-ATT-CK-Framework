# Mitre ATT&CK Threat Intelligence: Mapping TTPs of a Fileless Malware Attack

## Introduction
Cyber-attacks are becoming increasingly sophisticated, leveraging advanced tactics, techniques, and procedures (TTPs) to evade detection and maximize impact. This document explores the use of the MITRE ATT&CK framework to analyze a recent cyber-attack. The attack, titled "Cybercriminals Use Excel Exploit to Spread Fileless Remcos RAT Malware," highlights how threat actors exploit vulnerabilities, such as CVE-2017-0199, and leverage legitimate tools to deploy malicious payloads.

### Objective
To use the MITRE ATT&CK framework to map out the tactics, techniques, and procedures (TTPs) of a recent cyber-attack and provide actionable insights for detecting and mitigating similar threats.

### Task
Identify and describe the relevant tactics, techniques, and procedures (TTPs) used in the attack "Cybercriminals Use Excel Exploit to Spread Fileless Remcos RAT Malware" as detailed in the article available at [The Hacker News](https://thehackernews.com/2024/11/cybercriminals-use-excel-exploit-to.html).


**Remcos RAT** (Remote Control and Surveillance Software) is a commercially available remote access tool (RAT) that is often repurposed by cybercriminals for malicious activities. While marketed as legitimate software for system administration and monitoring, it is frequently used in cyber-attacks to gain unauthorized access, maintain persistence, and conduct espionage.

![Image](https://github.com/user-attachments/assets/e18db833-83f6-43d1-9f66-b441e221f430)













## Threat Mapping Using MITRE ATT&CK Framework

### Attack Summary
The attack leverages a malicious Excel file exploiting CVE-2017-0199 to deliver the Remcos RAT malware via fileless execution. By abusing legitimate tools and obfuscation techniques, the attackers bypass traditional detection mechanisms. Below is the detailed mapping of the attack's lifecycle to the MITRE ATT&CK framework.

| **Tactic**             | **Technique**                      | **Procedure**                                                                 |
|-------------------------|-------------------------------------|-------------------------------------------------------------------------------|
| Reconnaissance         | Phishing for Information           | Used purchase order-themed lures to convince recipients to open Excel files. |
| Resource Development   | Develop Capability                 | Used legitimate services like DocuSign to deceive users into signing documents. |
| Initial Access         | Phishing                          | Exploited CVE-2017-0199 via malicious Excel attachments.                      |
| Execution              | User Execution, Fileless Execution | Used mshta.exe to deploy HTA payloads wrapped in obfuscated scripts.         |
| Persistence            | Compromised Host Software          | Remcos RAT runs in memory, allowing continued access without file storage.    |
| Privilege Escalation   | Process Injection                  | Malicious code uses process hollowing to inject into process memory.          |
| Defense Evasion        | Obfuscation                        | Leveraged obfuscated PowerShell, JavaScript, and VBScript for in-memory execution. |
| Credential Access      | Exploitation for Credential Access | Remcos RAT harvests sensitive information remotely.                          |
| Discovery              | System Information Discovery       | Enumerates system metadata, processes, and gathers clipboard data.           |
| Lateral Movement       | Remote Services                    | Exploits network operations to move laterally within a network.              |
| Collection             | Input Capture                      | Gathers files, processes, and clipboard data.                                |
| Command and Control    | Remote Access Software             | Communicates with a C2 server to exfiltrate data and receive commands.       |
| Exfiltration           | File Exfiltration Over Web Service | Transfers collected files and data to the remote C2 server.                  |
| Impact                 | Data Manipulation, Financial Theft | Alters system functionality and gathers sensitive information for fraud.     |


## Recommendations

### Technical Mitigations
1. Deploy advanced email filtering solutions to detect phishing attempts.
2. Use Endpoint Detection and Response (EDR) tools to identify fileless execution techniques.
3. Patch known vulnerabilities such as CVE-2017-0199 across all systems.

### Process Improvements
1. Train employees on identifying phishing emails and potential attack vectors.
2. Regularly update threat intelligence feeds and integrate them with SIEM tools.

### Advanced Threat Hunting
1. Monitor PowerShell and mshta.exe activities for signs of abuse.
2. Analyze process injection techniques and lateral movement attempts in network logs.

### Policy and Compliance
1. Enforce least-privilege principles to minimize potential impacts of RATs.
2. Conduct regular audits of software and processes to identify unauthorized activities.


This project demonstrates the practical application of the MITRE ATT&CK framework in analyzing and mitigating cyber threats. By mapping the attack lifecycle to the framework, security teams can better understand and prepare for similar threats in the future. [Source: The Hacker News](https://thehackernews.com/2024/11/new-ymir-ransomware-exploits-memory-for.html)


## Thank you
Victoria Simon 
