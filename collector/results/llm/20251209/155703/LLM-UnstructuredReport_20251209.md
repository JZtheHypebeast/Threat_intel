# LLM Unstructured Threat Intelligence Report

_Source file: rawtext-20251209.json_

## 1. Hackers Exploit Ivanti Connect Secure Vulnerabilities to Spread MetaRAT Malware
_Source: https://gbhackers.com/metarat-malware/_

**Summary:** Hackers exploit Ivanti Connect Secure vulnerabilities to spread MetaRAT malware, a variant of PlugX, targeting Japanese shipping and transportation companies.
**MITRE Techniques:**
- N/A  (Initial Access)
- T1204 User Execution: Malware Transfer via Web Application (Execution)
- T1053 Scheduled Task/Job (Persistence)
- N/A  (Lateral Movement)

## 2. SAP Security Patch Day Fixes Critical Flaws in Solution Manager, NetWeaver & More
_Source: https://gbhackers.com/sap-security-patch-day-fixes-critical-flaws/_

**Summary:** SAP has released security patches for multiple critical vulnerabilities in its products, including SAP Solution Manager, NetWeaver, and others. The patches address issues such as code injection, sensitive data exposure, memory corruption, and more.
**MITRE Techniques:**
- N/A  (Initial Access)
- T1204 User Execution of Malicious Code (Execution)

## 3. New Vishing Attack Exploits Microsoft Teams and QuickAssist to Deploy .NET Malware
_Source: https://gbhackers.com/new-vishing-attack/_

**Summary:** A sophisticated vishing campaign uses social engineering and legitimate Microsoft tools to establish command execution chains, leading to the deployment of multi-stage .NET malware. Threat actors impersonate IT personnel in Microsoft Teams calls, convincing victims to launch Windows Quick Assist, which grants remote access. The attackers then deploy a fileless malware that executes entirely within memory.
**MITRE Techniques:**
- N/A Social Engineering (Initial Access)
- N/A Abuse of Functionality (Persistence)
- T1021 Remote Services (Execution)
- T1036 .NET Evasion Techniques (Command and Control)
**IOCs:**
- domain: ciscocyber[.]com/verify.php — C2 server
- IP address:  — Command and Control infrastructure

## 4. Malicious MCP Servers Enable Stealthy Prompt Injection to Drain System Resources
_Source: https://gbhackers.com/malicious-mcp-servers-enable-stealthy-prompt-injection/_

**Summary:** Researchers discovered vulnerabilities in the Model Context Protocol (MCP) sampling feature, enabling malicious servers to execute stealthy prompt injection attacks, drain computational resources, and compromise large language model applications.
**MITRE Techniques:**
- T1190 Server Software Component (Initial Access)
- N/A Prompt Injection (Execution)
**IOCs:**
- other: MCP sampling feature — Exploited protocol vulnerability
- url: https://gbhackers.com/malicious-mcp-servers-enable-stealthy-prompt-injection/ — Article URL
**Detections:**
- MCP sampling feature misuse: Monitor for anomalous token consumption patterns and abnormal system behavior
- LLM response manipulation: Monitor for changes in LLM responses and detect injected instructions
**Recommendations:**
- Implement comprehensive security measures, including enhanced validation of sampling requests and monitoring for anomalous token consumption patterns
- Regularly update and patch MCP-based systems to prevent exploitation of vulnerabilities

## 5. Malicious VS Code on Microsoft Registry Steals WiFi Passwords and Captures Screens
_Source: https://gbhackers.com/malicious-vs-code/_

**Summary:** A sophisticated malware campaign targets developers through Visual Studio Code Marketplace, using two seemingly innocent extensions to steal WiFi passwords and capture screens.
**MITRE Techniques:**
- N/A DLL Hijacking (Execution)
- T1574.001 DLL Hijacking (Execution)
**IOCs:**
- filename: extension.js — Malicious script in VS Code extension
- hash:  — The article does not provide any information about the malware's hash values.
**Detections:**
- Yurei ransomware filesystem behavior: Monitor for unusual activity on the user's AppData folder and look for signs of DLL hijacking or other suspicious behavior.
**Recommendations:**
- Developers should audit their installed extensions and remain vigilant against the growing threat of supply chain attacks within the VS Code ecosystem. Consider using a reputable extension management tool to prevent malicious extensions from being installed.

## 6. AI-Driven Tools Uncover GhostPenguin Backdoor Attacking Linux Servers
_Source: https://gbhackers.com/ai-driven-tools/_

**Summary:** A sophisticated Linux backdoor named GhostPenguin has been discovered by Trend Micro Research, evading detection for over four months. It delivers remote access and file system manipulation capabilities to threat actors.
**MITRE Techniques:**
- N/A Initial Access
- N/A Execution
**IOCs:**
- ip:  — Command and control server IP address
- domain:  — Command and control server domain name
**Detections:**
- GhostPenguin detection: Monitor network traffic for suspicious UDP communication through port 53
- System information collection: Monitor system calls for collection of sensitive information, such as IP addresses and OS versions
**Recommendations:**
- Implement robust network segmentation and monitoring to detect suspicious communication through port 53. Regularly update systems with latest security patches and maintain accurate system information.
- Establish a threat hunting pipeline that includes automated analysis of malware samples, extraction of artifacts, and deployment of custom YARA rules.

## 7. Burp Suite Upgrades Scanner With Detection for Critical React2Shell Flaws
_Source: https://gbhackers.com/burp-suite-upgrades-scanner-for-critical-react2shell-flaws/_

**Summary:** Burp Suite's ActiveScan++ extension has updated its scanner to detect critical React2Shell vulnerabilities (CVE-2025-55182 and CVE-2025-66478). This detection allows security testers to identify these vulnerabilities during routine scans without slowing down the testing process.
**MITRE Techniques:**
- N/A
**Detections:**
- React2Shell detection via ActiveScan++: Detect presence of React2Shell vulnerabilities using Burp Suite's ActiveScan++ extension during routine scans.
**Recommendations:**
- Update Burp Suite and its extensions, including ActiveScan++, to ensure detection capabilities for critical React2Shell vulnerabilities. Regularly scan networks and systems using the updated tool to identify potential vulnerabilities.

## 8. Akira Group Targets Hyper-V and VMware ESXi with Ransomware Exploiting Vulnerabilities
_Source: https://gbhackers.com/akira-group/_

**Summary:** The Akira ransomware group targets Hyper-V and VMware ESXi with ransomware exploiting vulnerabilities, particularly CVE-2024-37085, to compromise hypervisors and encrypt VMs.
**MITRE Techniques:**
- N/A Exploit a Vulnerability (Initial Access)
- T1204 User Execution (Execution)
**IOCs:**
- cve: CVE-2024-37085 — Vulnerability exploited by attackers.
- ip:  — No IP addresses mentioned in the article.
**Detections:**
- Hypervisor compromise detection: Monitor for suspicious activity on hypervisors and investigate any attempts to exploit CVE-2024-37085.
- VM encryption detection: Detect and alert on unusual network traffic patterns indicating VM encryption, such as sudden increases in encrypted data transfer.

## 9. North Korean hackers exploit React2Shell flaw in EtherRAT malware attacks
_Source: https://www.bleepingcomputer.com/news/security/north-korean-hackers-exploit-react2shell-flaw-in-etherrat-malware-attacks/_

**Summary:** North Korean hackers exploit React2Shell flaw in EtherRAT malware attacks, targeting 30 organizations across multiple sectors.
**MITRE Techniques:**
- N/A Exploitation of Vulnerability (Initial Access)
- T1059 Command and Control (C2) (Command and Control)
**IOCs:**
- url: https://nodejs.org/ — C2 server
- domain: ethereum.com — C2 server
**Detections:**
- Yurei ransomware filesystem behavior: Monitor for suspicious network activity related to Ethereum RPC traffic and Node.js communication.
- EtherRAT implant detection: Check for the presence of EtherRAT's persistence mechanisms on Linux systems, including Cron jobs, bashrc injection, XDG autostart, Systemd user service, and Profile injection.
**Recommendations:**
- Upgrade to a safe React/Next.js version as soon as possible to prevent exploitation of the React2Shell flaw.
- Rotate credentials and monitor Ethereum RPC traffic to detect potential C2 activity.

## 10. Microsoft investigates Copilot outage affecting users in Europe
_Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-investigates-copilot-outage-affecting-users-in-europe/_

**Summary:** Microsoft is investigating an outage affecting users in Europe who are unable to access the Copilot digital assistant or experience degraded functionality.
**MITRE Techniques:**
- N/A  (None)

## 11. Ransomware IAB abuses EDR for stealthy malware execution
_Source: https://www.bleepingcomputer.com/news/security/ransomware-iab-abuses-edr-for-stealthy-malware-execution/_

**Summary:** Ransomware IAB Storm 0249 abuses EDR solutions and Microsoft utilities for stealthy malware execution, enabling persistence and evasion of security tools.
**MITRE Techniques:**
- N/A DLL Side Loading (Persistence)
- N/A Abuse of Trusted Tools (Initial Access)
**IOCs:**
- domain: a spoofed Microsoft domain — Used in the PowerShell script to fetch a malicious DLL.
- hash: SentinelAgentCore.dll — Dropped by the MSI package.
**Detections:**
- Stealthy malware execution via EDR components: Monitor trusted processes loading unsigned DLLs from non-standard paths; set stricter controls for curl, PowerShell, and LoLBin execution.
**Recommendations:**
- Implement behavior-based detection to identify trusted processes loading unsigned DLLs from non-standard paths. Set stricter controls for curl, PowerShell, and LoLBin execution.

## 12. New Variant of Mirai Botnet ‘Broadside’ Launches Active Attacks on Users
_Source: https://gbhackers.com/mirai-botnet-2/_

**Summary:** A new variant of the Mirai botnet, dubbed 'Broadside,' has launched active attacks on users, specifically targeting maritime logistics sector by exploiting CVE-2024-3721 vulnerability in digital video recorders (DVRs) used on commercial vessels.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- T1204 User Execution: Malware Delivery by Email (Phishing) (Execution)
- N/A Unknown (Persistence)
**IOCs:**
- domain: /device.rsp — Exploited vulnerability endpoint
- url: http:// — Attack vector HTTP POST request
**Detections:**
- Broadside malware detection: Monitor network traffic for C2 communications over TCP port 1026 (backup port 6969)
- CVE-2024-3721 exploit detection: Monitor endpoint activity for exploitation of CVE-2024-3721 vulnerability

## 13. FinCEN says ransomware gangs extorted over $2.1B from 2022 to 2024
_Source: https://www.bleepingcomputer.com/news/security/fincen-says-ransomware-gangs-extorted-over-21b-from-2022-to-2024/_

**Summary:** FinCEN reported that ransomware gangs extorted over $2.1B from 2022 to 2024, with law enforcement operations targeting BlackCat and LockBit gangs contributing to a decrease in ransom payments.
**MITRE Techniques:**
- N/A Unknown
**IOCs:**
- domain: Akira — Ransomware gang mentioned in the article.
- domain: BlackCat/ALPHV — Ransomware gang mentioned in the article.
**Detections:**
- Monitor ransom payment attempts via Bitcoin and other cryptocurrencies.: Detect suspicious transactions, especially those involving ransom payments in cryptocurrency.
- Identify and isolate potential entry points for exploitation.: Analyze network logs to identify potential vulnerabilities or exploits used by attackers.
**Recommendations:**
- Continue reporting attacks to the FBI and ransom payments to FinCEN to help disrupt cybercrime.
- Monitor network activity for suspicious transactions, especially those involving cryptocurrency.

## 14. Malicious VSCode extensions on Microsoft's registry drop infostealers
_Source: https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-on-microsofts-registry-drop-infostealers/_

## 15. Ransomware gangs turn to Shanya EXE packer to hide EDR killers
_Source: https://www.bleepingcomputer.com/news/security/ransomware-gangs-turn-to-shanya-exe-packer-to-hide-edr-killers/_

**Summary:** Ransomware gangs are using a packer-as-a-service platform named Shanya to hide EDR killers, making it harder for security tools to detect their payloads.
**MITRE Techniques:**
- N/A Packer as a service (Initial Access)
- N/A DLL side loading (Execution)
- N/A Privilege escalation (Persistence)
- N/A Security product disabling (Impact)
**IOCs:**
- other: Shanya packer operation — The Shanya packer operation is mentioned in the article as a service used by ransomware gangs.
- filename: msimg32.dll — The filename msimg32.dll is mentioned as one of the malicious DLLs packed with Shanya.
**Detections:**
- Yurei ransomware filesystem behavior: Monitor for suspicious network traffic and unusual system calls, especially if the system is running a Shanya-packed DLL.
**Recommendations:**
- Implement EDR solutions that can detect and prevent Shanya-packed payloads from evading detection. Regularly update antivirus engines to ensure they can detect new variants of malware using Shanya.

## 16. Poland arrests Ukrainians utilizing 'advanced' hacking equipment
_Source: https://www.bleepingcomputer.com/news/security/poland-arrests-ukrainians-utilizing-advanced-hacking-equipment/_

**Summary:** Poland arrested three Ukrainian nationals for allegedly using advanced hacking equipment, including a Flipper Zero device, to interfere with the country's strategic IT systems.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
**IOCs:**
- other: Flipper Zero — Portable tool for pentesting and hardware hacking
- ip: 
**Detections:**
- Flipper Zero Device Detection: Monitor for the presence of a Flipper Zero device on the network and investigate any suspicious activity.
**Recommendations:**
- Implement additional security measures to protect against advanced hacking equipment, such as network segmentation and access controls.

## 17. Storm-0249 Escalates Ransomware Attacks with ClickFix, Fileless PowerShell, and DLL Sideloading
_Source: https://thehackernews.com/2025/12/storm-0249-escalates-ransomware-attacks.html_

**Summary:** Storm-0249 ransomware group shifts tactics, using domain spoofing, DLL sideloading, and fileless PowerShell execution to facilitate attacks, posing serious concerns for security teams.
**MITRE Techniques:**
- N/A
- T1190 Exploit Public-Facing Application (Initial Access)
- N/A
**IOCs:**
- domain: sgcipl[.]com/us.microsoft.com/bdo/ — C2 server URL
- dll: SentinelAgentCore.dll — Trojanized DLL dropped by malicious MSI package
**Detections:**
- Yurei ransomware filesystem behavior: Look for suspicious file activity on endpoints, especially related to Yurei ransomware indicators
**Recommendations:**
- Implement robust security measures to prevent initial access broker tactics, including multi-factor authentication and regular software updates

## 18. Hackers Using FLIPPER Devices to Breach IT Systems Arrested by Authorities
_Source: https://gbhackers.com/hackers-using-flipper-devices-to-breach-arrested-by-authorities/_

**Summary:** Polish authorities arrested three Ukrainian citizens with sophisticated hacking equipment, including FLIPPER devices, during a routine traffic stop. The suspects were planning to conduct cyberattacks against critical infrastructure in Europe.
**MITRE Techniques:**
- N/A Unknown
**IOCs:**
- other: FLIPPER devices — Advanced hacking equipment
- domain: linkedin.com — Used for social engineering
**Detections:**
- FLIPPER device detection: Monitor network traffic for suspicious activity related to FLIPPER devices
- Suspicious behavior detection: Look for patterns of behavior consistent with cybercriminals, such as evasive responses and inconsistent statements
**Recommendations:**
- Implement advanced threat detection tools to identify FLIPPER devices and other hacking equipment. Train staff on recognizing suspicious behavior in network traffic.

## 19. Google Chrome adds new security layer for Gemini AI agentic browsing
_Source: https://www.bleepingcomputer.com/news/security/google-chrome-adds-new-security-layer-for-gemini-ai-agentic-browsing/_

**Summary:** Google Chrome introduces a new security layer called User Alignment Critic to protect agentic AI browsing features powered by Gemini, which mitigates the risk of indirect prompt injection and includes user oversight and prompt injection detection.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- T1218 Server Software Component (Persistence)
- N/A Unknown (Lateral Movement)
**IOCs:**
- other: Gemini AI assistant — Used for agentic browsing in Chrome
- other: User Alignment Critic — New security layer in Chrome to prevent indirect prompt injection
**Detections:**
- Gemini AI assistant activity: Monitor for suspicious activity related to Gemini AI assistant, such as unexpected changes in browser behavior or unusual network connections.
- User Alignment Critic alerts: Monitor for alerts generated by User Alignment Critic, which may indicate potential security threats or suspicious activity.
**Recommendations:**
- Implement the new security layer, User Alignment Critic, in Chrome to prevent indirect prompt injection and protect user data.
- Regularly monitor for suspicious activity related to Gemini AI assistant and take corrective action as needed.

## 20. How to Streamline Zero Trust Using the Shared Signals Framework
_Source: https://thehackernews.com/2025/12/how-to-streamline-zero-trust-using.html_

**Summary:** The article discusses implementing a Shared Signals Framework (SSF) to help security tools communicate with each other. It provides a step-by-step guide on how to configure the SSF using Tines, a workflow orchestration and AI platform.

## 21. React2Shell Attacks Linked to North Korean Hackers
_Source: https://www.securityweek.com/react2shell-attacks-linked-to-north-korean-hackers/_

**Summary:** North Korean threat actors are exploiting CVE-2025-55182 to deliver the EtherRAT malware.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Execution)
**IOCs:**
- cve: CVE-2025-55182 — Exploited vulnerability
- other: EtherRAT malware — Delivered payload
**Detections:**
- EtherRAT malware delivery detection: Monitor for suspicious network activity related to the exploitation of CVE-2025-55182 and the delivery of EtherRAT malware.
- Vulnerability exploitation detection: Look for signs of vulnerability exploitation, such as unusual system calls or API usage, related to CVE-2025-55182.
**Recommendations:**
- Patch CVE-2025-55182 and monitor for suspicious network activity related to the delivery of EtherRAT malware.
- Review and update incident response plans to address state-sponsored attacks and malware delivery.

## 22. Researchers Find Malicious VS Code, Go, npm, and Rust Packages Stealing Developer Data
_Source: https://thehackernews.com/2025/12/researchers-find-malicious-vs-code-go.html_

**Summary:** Cybersecurity researchers have discovered malicious packages on Microsoft Visual Studio Code (VS Code) Marketplace that steal developer data, including code, emails, Slack DMs, WiFi passwords, and browser sessions.
**MITRE Techniques:**
- N/A Unknown
**IOCs:**
- domain: syn1112223334445556667778889990[.]org — C2 server
- url: github.com/bpoorman/uuid — malicious package
**Detections:**
- VS Code extension activation detection: Monitor VS Code extension activity for suspicious behavior, such as excessive data transfer or unusual network connections.
- Malicious package identification: Scan endpoints for known malicious packages and monitor for new package installations.
**Recommendations:**
- Regularly update VS Code extensions and packages, and use reputable sources when installing software. Use antivirus software to detect and remove malware. Implement robust endpoint detection and response (EDR) solutions to monitor for suspicious activity.

## 23. Identity Security Firm Saviynt Raises $700 Million at $3 Billion Valuation
_Source: https://www.securityweek.com/identity-security-firm-saviynt-raises-700-million-at-3-billion-valuation/_

**Summary:** Saviynt, an identity security firm, raised $700 million in funding at a valuation of $3 billion.

## 24. US Posts $10 Million Bounty for Iranian Hackers
_Source: https://www.securityweek.com/us-posts-10-million-bounty-for-iranian-hackers/_

**Summary:** The US government is offering a $10 million reward for information leading to the disruption or prosecution of Emennet Pasargad hackers, particularly its leader Mohammad Bagher Shirinkar.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Execution)
**IOCs:**
- other: Emennet Pasargad — Group name mentioned as target of the bounty.
- other: Mohammad Bagher Shirinkar — Individual mentioned as leader of Emennet Pasargad.
**Detections:**
- Emennet Pasargad group activity detection: Monitor for suspicious activity and connections related to Emennet Pasargad, such as phishing attempts or unusual network traffic patterns.

## 25. Proofpoint Completes $1.8 Billion Acquisition of Hornetsecurity
_Source: https://www.securityweek.com/proofpoint-completes-1-8-billion-acquisition-of-hornetsecurity/_

**Summary:** Proofpoint acquires Hornetsecurity for $1.8 billion, bringing in nearly $200 million in annual recurring revenue.

## 26. Google Adds Layered Defenses to Chrome to Block Indirect Prompt Injection Threats
_Source: https://thehackernews.com/2025/12/google-adds-layered-defenses-to-chrome.html_

**Summary:** Google adds layered defenses to Chrome to block indirect prompt injection threats that could lead to data exfiltration or hijacking of user goals.
**MITRE Techniques:**
- N/A Malicious use of AI/ML (Lateral Movement)
- N/A Cross-Site Scripting (XSS) (Execution)
**IOCs:**
- URL: https://example.com/malicious-content
- Agent Origin Set: [origin-set-value]

## 27. Over 300,000 Individuals Impacted by Vitas Hospice Data Breach
_Source: https://www.securityweek.com/over-300000-individuals-impacted-by-vitas-hospice-data-breach/_

**Summary:** Vitas, the largest for-profit hospice chain in the US, experienced a data breach affecting over 300,000 individuals.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Execution)
**IOCs:**
- other: Vitas Hospice — Organization affected by the data breach
- other: SecurityWeek — Source of the article
**Detections:**
- Unusual network traffic from Vitas Hospice: Monitor network traffic for suspicious activity related to Vitas Hospice
- Unauthorized access to sensitive data: Monitor endpoint logs for unauthorized access to sensitive data
**Recommendations:**
- Vitas Hospice should conduct a thorough investigation into the breach and implement measures to prevent future incidents.
- Individuals affected by the breach should be informed of the incident and provided with guidance on how to protect their personal information.

## 28. Equixly Raises $11 Million for AI-Powered API Penetration Testing
_Source: https://www.securityweek.com/equixly-raises-11-million-for-ai-powered-api-penetration-testing/_

**Summary:** Equixly, an Italian startup, raised $11 million to develop AI-powered API penetration testing tools.

## 29. New ‘Broadside’ Botnet Poses Risk to Shipping Companies
_Source: https://www.securityweek.com/new-broadside-botnet-poses-risk-to-shipping-companies/_

**Summary:** The Broadside botnet targets shipping companies by stealing credentials from infected TBK DVR devices and launching DDoS attacks.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Persistence)
- T1190 Exploit Public-Facing Application (Initial Access)
**IOCs:**
- domain: TBK DVR devices — C2 server or vulnerable endpoint
**Detections:**
- Broadside botnet detection: Monitor DVR devices for suspicious activity, such as unauthorized access or DDoS attacks.
**Recommendations:**
- Update DVR device firmware to prevent exploitation. Implement network segmentation and monitor for DDoS attacks.

## 30. Experts Confirm JS#SMUGGLER Uses Compromised Sites to Deploy NetSupport RAT
_Source: https://thehackernews.com/2025/12/experts-confirm-jssmuggler-uses.html_

**Summary:** Cybersecurity researchers confirm a new campaign dubbed JS#SMUGGLER that uses compromised websites to deploy the NetSupport RAT remote access trojan.
**MITRE Techniques:**
- N/A  (Initial Access)
- N/A  (Execution)
**IOCs:**
- domain: phone.js — C2 server
- url: https://thehackernews.com/2025/12/experts-confirm-jssmuggler-uses.html — Article URL
**Detections:**
- JavaScript Loader Detection: Monitor for suspicious JavaScript loaders and HTA files executing on compromised hosts.
- PowerShell Stager Detection: Monitor for PowerShell stagers and malicious payloads executing on compromised hosts.
**Recommendations:**
- 
- 

## 31. STAC6565 Targets Canada in 80% of Attacks as Gold Blade Deploys QWCrypt Ransomware
_Source: https://thehackernews.com/2025/12/stac6565-targets-canada-in-80-of.html_

**Summary:** A new campaign has been discovered that uses legitimate job search platforms to deliver malware. The attackers are targeting human resources personnel with spear phishing emails containing malicious documents disguised as resumes or cover letters.

## 32. Google Fortifies Chrome Agentic AI Against Indirect Prompt Injection Attacks
_Source: https://www.securityweek.com/google-fortifies-chrome-agentic-ai-against-indirect-prompt-injection-attacks/_

**Summary:** Google has fortified Chrome's agentic AI against indirect prompt injection attacks with new features including user alignment critic, expanded origin isolation capabilities, and user confirmations.
**MITRE Techniques:**
- N/A  (Initial Access)

## 33. NCSC-2025-0382 [1.00] [M/H] Kwetsbaarheden verholpen in Siemens producten
_Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0382_

**Summary:** The Dutch National Cyber Security Centre (NCSC) has identified vulnerabilities in Siemens products that have been patched.
**MITRE Techniques:**
- N/A Unknown technique (Initial Access)
**Detections:**
- Unpatched Siemens systems: Check for unpatched Siemens systems and apply the latest patches.
**Recommendations:**
- Apply the latest security patches to prevent exploitation of vulnerabilities in Siemens products.
