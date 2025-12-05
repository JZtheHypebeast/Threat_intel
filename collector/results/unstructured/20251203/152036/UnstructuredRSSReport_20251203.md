## Summary

- Total findings: 40



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 3
**Data Completeness:** 92% (37/40 entries have threats+actors+MITRE)

Entry 1
- [1] Examining the Risk of AI-Assisted MedusaLocker Ransomware Attacks
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 13:05:28, 13:05:30, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 12:53:46, 12:35:01
  - Source: https://gbhackers.com/medusalocker-ransomware/

Entry 2
- [2] Longwatch RCE Flaw Allows Attackers to Run Remote Code with Elevated Privileges
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1116 — Code Signing 
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1589.001 — Credentials
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit 
    - T1589.001: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - malware: SYSTEM
    - ip: 10:51:58, 10:52:00, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 13:05:28
  - Source: https://gbhackers.com/longwatch-rce-flaw/

Entry 3
- [3] Let’s Encrypt Cutting Certificate Lifespan from 90 Days to 45 Days
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1596.003 — Digital Certificates 
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1589.001 — Credentials
  - Mitigations:
    - T1596.003: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit 
    - T1589.001: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - malware: PERSIST
    - ip: 12:26:00, 12:26:03, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 13:05:28
  - Source: https://gbhackers.com/lets-encrypt-cutting-certificate-lifespan-from-90-days-to-45-days/

Entry 4
- [4] Shai-Hulud 2.0 Cyberattack Compromises 30,000 Repos and Exposes 500 GitHub Accounts
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 12:00:44, 12:00:46, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 13:05:28, 12:53:46
  - Source: https://gbhackers.com/shai-hulud-2-0/

Entry 5
- [5] Microsoft Confirms Windows 11 25H2 UI Features Broken also Along With 24H2 Following Update
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1589.001 — Credentials
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit 
    - T1589.001: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 12:53:46, 12:53:48, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 13:05:28, 12:35:01
  - Source: https://gbhackers.com/microsoft-confirms-windows-11-25h2-ui-features/

Entry 6
- [6] Malicious Rust “evm-units” Impersonator Deploys OS-Specific Payloads
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1143 — Hidden Window 
    - T1588.006 — Vulnerabilities 
    - T1059.002 — AppleScript 
    - T1195 — Supply Chain Compromise 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1059.002: Code Signing 
    - T1195: Boot Integrity 
    - T1036: Audit 
    - T1059.001: Disable or Remove Feature or Program
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - filename: qhsafetray.exe
    - malware: CREATE_NO_WINDOW
    - ip: 11:23:26, 11:23:28, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12
  - Source: https://gbhackers.com/evm-units/

Entry 7
- [7] New Calendly-Inspired Phishing Attack Aims to Steal Google Workspace Credentials
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1583.008 — Malvertising 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials
  - Mitigations:
    - T1583.008: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1583.001: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - malware: CAPTCHA
    - ip: 12:35:01, 12:35:03, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 13:05:28
  - Source: https://gbhackers.com/calendly-inspired-phishing/

Entry 8
- [8] CISA Issues Alert on Actively Exploited Android Zero-Day Vulnerability
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise
  - Enablers: ai, artificial intelligence, zero-day
  - IOCs:
    - ip: 13:30:12, 13:30:13, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:05:28, 12:53:46, 12:35:01
  - Source: https://gbhackers.com/android-zero-day/

Entry 9
- [9] Massive Phishing Attack Uses Parking Ticket and Medical Test Themes, Attributed to Storm-0900
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1204.001 — Malicious Link 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 10:35:10, 10:35:12, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33, 13:30:12, 13:05:28, 12:53:46
  - Source: https://gbhackers.com/phishing-attack-2/

Entry 10
- [10] Deep dive into DragonForce ransomware and its Scattered Spider connection
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Medium (50)
  - MITRE Techniques:
    - T1213.002 — Sharepoint 
    - T1588.006 — Vulnerabilities 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.002: Audit 
    - T1588.006: Pre-compromise 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, s3
  - IOCs:
    - ip: 10:05:15, 10:14:51, 09.22.24.2
    - domain: truesight.sys, rentdrv2.sys
  - Source: https://www.bleepingcomputer.com/news/security/deep-dive-into-dragonforce-ransomware-and-its-scattered-spider-connection/

Entry 11
- [11] Threat Actors Using Matanbuchus Downloader to Deliver Ransomware and Maintain Persistence
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1053.005 — Scheduled Task 
    - T1219 — Remote Access Software 
    - T1204.002 — User Execution: Malicious File 
    - T1588.006 — Vulnerabilities 
    - T1218.007 — Msiexec 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1059.001 — PowerShell 
    - T1678 — Delay Execution 
    - T1566 — Phishing 
    - T1110 — Brute Force 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1574.002 — DLL Side-Loading 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1053.005: Privileged Account Management 
    - T1219: Execution Prevention 
    - T1204.002: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1218.007: Disable or Remove Feature or Program
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - filename: HRUpdate.exe
    - malware: APPDATA, SHA256
    - ip: 10:08:00, 10:08:02, 15:02:00, 10:32:00, 03:51:44, 06:13:05, 13:09:33
  - Source: https://gbhackers.com/matanbuchus-downloader/

Entry 12
- [12] Aisuru botnet behind new record-breaking 29.7 Tbps DDoS attack
  - Category: DDoS/Botnet
  - Relevance: Critical (100)
  - Actionability: Informational (24)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1589.001 — Credentials
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1589.001: Pre-compromise
  - Enablers: ai
  - IOCs:
    - ip: 09:01:04, 12:40:34, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/security/aisuru-botnet-behind-new-record-breaking-297-tbps-ddos-attack/

Entry 13
- [13] FTC settlement requires Illuminate to delete unnecessary student data
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1557.004 — Evil Twin 
    - T1589.002 — Email Addresses 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.006: User Training 
    - T1557.004: Network Intrusion Prevention 
    - T1589.002: Pre-compromise 
    - T1566: Audit 
    - T1592.002: Pre-compromise
  - Enablers: ai, cloud, phishing
  - IOCs:
    - ip: 15:50:13, 15:53:13, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/security/ftc-settlement-requires-illuminate-to-delete-unnecessary-student-data/

Entry 14
- [14] Critical RSC Bugs in React and Next.js Allow Unauthenticated Remote Code Execution
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (45)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs:
    - ip: 23:49:00, 18:19:14
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/critical-rsc-bugs-in-react-and-nextjs.html

Entry 15
- [15] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, zero day, cloud
  - IOCs:
    - ip: 23:16:00, 17:47:08
    - filename: of.lnk, an.lnk
  - Source: https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html

Entry 16
- [16] WordPress King Addons Flaw Under Active Attack Lets Hackers Make Admin Accounts
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs:
    - ip: 2602:fa59:3:424::1, 22:38:00, 17:09:52, 45.61.157.120, 182.8.226.228, 138.199.21.230, 206.238.221.25
    - filename: ajax.php
  - Source: https://thehackernews.com/2025/12/wordpress-king-addons-flaw-under-active.html

Entry 17
- [17] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise 
    - T1589.001: Pre-compromise
  - Enablers: ai, artificial intelligence, cloud
  - IOCs:
    - ip: 23:26:00, 17:56:24
  - Source: https://thehackernews.com/2025/12/discover-ai-tools-fueling-next.html

Entry 18
- [18] Brazil Hit by Banking Trojan Spread via WhatsApp Worm and RelayNFC NFC Relay Fraud
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1204.002 — User Execution: Malicious File 
    - T1047 — Windows Management Instrumentation 
    - T1113 — Screen Capture 
    - T1093 — Process Hollowing 
    - T1021.007 — Cloud Services 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1059.006 — Python 
    - T1059.005 — Visual Basic 
    - T1566.001 — Spearphishing Attachment 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1204.002: Execution Prevention 
    - T1047: Privileged Account Management 
    - T1021.007: Multi-factor Authentication 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit
  - Enablers: ai, artificial intelligence, cryptocurrency
  - IOCs:
    - filename: svchost.exe
    - ip: 21:02:00, 16:46:32
    - domain: executed.dat, test.ikotech, manoelimoveiscaioba.com, serverseistemasatu.com, maisseguraca.site, test.ikotech.online
  - Source: https://thehackernews.com/2025/12/brazil-hit-by-banking-trojan-spread-via.html

Entry 19
- [19] Chopping AI Down to Size: Turning Disruptive Technology into a Strategic Advantage
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1059.006 — Python
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise 
    - T1059.006: Audit
  - Enablers: ai, artificial intelligence, machine learning
  - IOCs:
    - ip: 15:26:00, 09:56:18
  - Source: https://thehackernews.com/2025/12/chopping-ai-down-to-size-turning.html

Entry 20
- [20] Picklescan Bugs Allow Malicious PyTorch Models to Evade Scans and Execute Code
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1090 — Proxy 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1059.006 — Python 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1090: Filter Network Traffic 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, machine learning, cloud
  - IOCs:
    - ip: 15:00:00, 11:44:01
    - domain: as.bin, or.pt, linecache.getline
  - Source: https://thehackernews.com/2025/12/picklescan-bugs-allow-malicious-pytorch.html

Entry 21
- [21] Malicious Rust Crate Delivers OS-Specific Malware to Web3 Developer Systems
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (20)
  - MITRE Techniques:
    - T1036 — Masquerading 
    - T1021.007 — Cloud Services 
    - T1059.001 — PowerShell 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1059.005 — Visual Basic
  - Mitigations:
    - T1036: Audit 
    - T1021.007: Multi-factor Authentication 
    - T1059.001: Disable or Remove Feature or Program 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: ai, cryptocurrency, cloud
  - IOCs:
    - filename: qhsafetray.exe
    - ip: 14:09:00, 08:39:41
    - domain: crates.io, download.videotalks, download.videotalks.xyz
  - Source: https://thehackernews.com/2025/12/malicious-rust-crate-delivers-os.html

Entry 22
- [22] [webapps] phpMyFaq 2.9.8 - Cross Site Request Forgery (CSRF)
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (40)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/thorsten/phpmyfaq/, http://phpmyfaq/admin/index.php
    - email: attacker@example.com
    - domain: github.com, example.com, document.forms
    - filename: index.php, poc.html
  - Source: https://www.exploit-db.com/exploits/52455

Entry 23
- [23] [webapps] phpMyFAQ 2.9.8 - Cross-Site Request Forgery(CSRF)
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (50)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/thorsten/phpmyfaq, http://phpmyfaq/admin/index.php?action=clear, http://phpmyfaq/admin/index.php
    - domain: github.com, document.forms
    - filename: index.php, stat.main.php
  - Source: https://www.exploit-db.com/exploits/52459

Entry 24
- [24] [webapps] MaNGOSWebV4  4.0.6 - Reflected XSS
  - Category: Cross-Site Scripting
  - Relevance: Critical (100)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/paintballrefjosh/mangoswebv4, http://mangoswebv4/install/index.php?step=%3cscript%3ealert
    - domain: github.com
    - filename: index.php
  - Source: https://www.exploit-db.com/exploits/52457

Entry 25
- [25] [webapps] Django 5.1.13 - SQL Injection
  - Category: Injection
  - Relevance: Critical (100)
  - Actionability: Medium (33)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1059.006 — Python
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1059.006: Audit
  - IOCs:
    - malware: DEFAULT_BASELINE, DEFAULT_PAYLOADS, DOTALL, VULNERABLE
    - ip: 127.0.0.1
    - url: https://www.djangoproject.com/, https://www.djangoproject.com/download/, http://target/, http://127.0.0.1
    - domain: djangoproject.com
  - Source: https://www.exploit-db.com/exploits/52456

Entry 26
- [26] [webapps] phpMyFAQ  2.9.8 - Cross-Site Request Forgery (CSRF)
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (50)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/thorsten/phpmyfaq, http://phpmyfaq/admin/index.php?action=updateglossary
    - domain: github.com, document.forms
    - filename: index.php, glossary.main.php, glossary.edit.php
  - Source: https://www.exploit-db.com/exploits/52458

Entry 27
- [27] [webapps] MobileDetect 2.8.31 - Cross-Site Scripting (XSS)
  - Category: Cross-Site Scripting
  - Relevance: Critical (100)
  - Actionability: High (70)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1064 — Scripting 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/serbanghita/mobile, http://mobiledetect/examples/session_example.php/%22%3e%3cscript%3ealert
    - domain: github.com, document.domain
  - Source: https://www.exploit-db.com/exploits/52454

Entry 28
- [28] [webapps] phpIPAM 1.4 - SQL-Injection
  - Category: Injection
  - Relevance: Critical (100)
  - Actionability: Medium (58)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1090 — Proxy 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.006: User Training 
    - T1090: Filter Network Traffic 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - malware: PHPSESSID, SELECT
    - url: https://github.com/phpipam/phpipam/
    - domain: github.com
    - filename: order.php
  - Source: https://www.exploit-db.com/exploits/52453

Entry 29
- [29] [webapps] RosarioSIS 6.7.2 - Cross Site Scripting (XSS)
  - Category: Cross-Site Scripting
  - Relevance: Critical (100)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1064 — Scripting 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://gitlab.com/francoisjacquet/rosariosis, http://rosariosis/modules.php?modname=users/preferences.php&tab=%22%20onmouseover%3dalert%281%29%20x%3d%22
    - domain: gitlab.com
    - filename: modules.php, preferences.php, warehous.php
  - Source: https://www.exploit-db.com/exploits/52450

Entry 30
- [30] [webapps] phpMyAdmin 5.0.0 - SQL Injection
  - Category: Injection
  - Relevance: Critical (100)
  - Actionability: Medium (58)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1090 — Proxy 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1090: Filter Network Traffic 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/phpmyadmin/phpmyadmin/
    - domain: github.com
  - Source: https://www.exploit-db.com/exploits/52451

Entry 31
- [31] [webapps] openSIS Community Edition 8.0 - SQL Injection
  - Category: Injection
  - Relevance: Critical (100)
  - Actionability: Medium (58)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1090 — Proxy 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1090: Filter Network Traffic 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/os4ed/opensis
    - domain: github.com
    - filename: forgotpassusername.php
  - Source: https://www.exploit-db.com/exploits/52447

Entry 32
- [32] [webapps] OpenRepeater 2.1 - OS Command Injection
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (40)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - malware: TARGET_URL, PAYLOAD
    - url: https://github.com/openrepeater/openrepeater, http://openrepeater/functions/ajax_system.php
    - domain: github.com
  - Source: https://www.exploit-db.com/exploits/52452

Entry 33
- [33] [webapps] RosarioSIS 6.7.2 - Cross-Site Scripting (XSS)
  - Category: Cross-Site Scripting
  - Relevance: Critical (100)
  - Actionability: High (70)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1064 — Scripting 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://gitlab.com/francoisjacquet/rosariosis, http://rosariosis/modules.php?modname=scheduling/printschedules.php&search_modfunc=list&include_inactive=
    - domain: gitlab.com
    - filename: modules.php, printschedules.php
  - Source: https://www.exploit-db.com/exploits/52449

Entry 34
- [34] [webapps] PluckCMS 4.7.10 - Unrestricted File Upload
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (40)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1090 — Proxy 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1090: Filter Network Traffic 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - malware: PHPSESSID
    - url: https://github.com/pluck, http://pluck/files/exploit_copy.php?cmd=id
    - domain: github.com, exploit.php.jpg
    - filename: admin.php
  - Source: https://www.exploit-db.com/exploits/52448

Entry 35
- [35] Microsoft "mitigates" Windows LNK flaw exploited as zero-day
  - Category: Phishing
  - Relevance: Critical (82)
  - Actionability: High (67)
  - MITRE Techniques:
    - T1553.005 — Mark-of-the-Web Bypass 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1553.005: Disable or Remove Feature or Program 
    - T1566.001: Antivirus/Antimalware
  - Enablers: ai, zero-day, zero day
  - IOCs:
    - ip: 11:45:30, 11:50:22, 09.22.24.2
    - filename: block.lnk, handles.lnk, windows.lnk
  - Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-mitigates-windows-lnk-flaw-exploited-as-zero-day/

Entry 36
- [36] Korea arrests suspects selling intimate videos from hacked IP cameras
  - Category: Other
  - Relevance: Critical (82)
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1557.004 — Evil Twin 
    - T1592.003 — Firmware
  - Mitigations:
    - T1557.004: Network Intrusion Prevention 
    - T1592.003: Pre-compromise
  - Enablers: ai
  - IOCs:
    - ip: 16:42:48, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/security/korea-arrests-suspects-selling-intimate-videos-from-hacked-ip-cameras/

Entry 37
- [37] University of Phoenix discloses data breach after Oracle hack
  - Category: Other
  - Relevance: High (61)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1566 — Phishing
  - Mitigations:
    - T1566: Audit
  - Enablers: ai, zero day, phishing
  - IOCs:
    - ip: 08:23:10, 10:24:47, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/security/university-of-phoenix-discloses-data-breach-after-oracle-hack/

Entry 38
- [38] Google expands Android scam protection feature to Chase, Cash App in U.S.
  - Category: Other
  - Relevance: Medium (36)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - ip: 12:00:00, 12:23:30, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/security/google-expands-android-scam-protection-feature-to-chase-cash-app-in-us/

Entry 39
- [39] ChatGPT is down worldwide, conversations disappeared for users
  - Category: Other
  - Relevance: Medium (34)
  - Actionability: Medium (30)
  - Mitigations: --
  - Enablers: ai, artificial intelligence
  - IOCs:
    - ip: 14:52:16, 04:45:57, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/artificial-intelligence/chatgpt-is-down-worldwide-conversations-disappeared-for-users/

Entry 40
- [40] Russia blocks Roblox over distribution of LGBT "propaganda"
  - Category: Ransomware
  - Relevance: Medium (32)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: ai, zero day
  - IOCs:
    - ip: 12:33:57, 09.22.24.2
  - Source: https://www.bleepingcomputer.com/news/security/russia-blocks-roblox-over-distribution-of-lgbt-propaganda/