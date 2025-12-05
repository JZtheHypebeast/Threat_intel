## Summary

- Total findings: 60



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 6
**Data Completeness:** 90% (54/60 entries have threats+actors+MITRE)

Entry 1
- [1] Let’s Encrypt Cutting Certificate Lifespan from 90 Days to 45 Days
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
  - Source: https://gbhackers.com/lets-encrypt-cutting-certificate-lifespan-from-90-days-to-45-days/

Entry 2
- [2] Examining the Risk of AI-Assisted MedusaLocker Ransomware Attacks
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
  - IOCs: --
  - Source: https://gbhackers.com/medusalocker-ransomware/

Entry 3
- [3] Microsoft Confirms Windows 11 25H2 UI Features Broken also Along With 24H2 Following Update
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
    - filename: explorer.exe
    - domain: client.cbs, microsoft.ui.xaml.cbs, windows.client.core
  - Source: https://gbhackers.com/microsoft-confirms-windows-11-25h2-ui-features/

Entry 4
- [4] Longwatch RCE Flaw Allows Attackers to Run Remote Code with Elevated Privileges
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
  - Source: https://gbhackers.com/longwatch-rce-flaw/

Entry 5
- [5] CISA Issues Alert on Actively Exploited Android Zero-Day Vulnerability
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
  - IOCs: --
  - Source: https://gbhackers.com/android-zero-day/

Entry 6
- [6] Shai-Hulud 2.0 Cyberattack Compromises 30,000 Repos and Exposes 500 GitHub Accounts
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
    - filename: environment.json, contents.json, trufflesecrets.json
    - domain: org.mvnpm
  - Source: https://gbhackers.com/shai-hulud-2-0/

Entry 7
- [7] Malicious Rust “evm-units” Impersonator Deploys OS-Specific Payloads
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
    - domain: crates.io
  - Source: https://gbhackers.com/evm-units/

Entry 8
- [8] New Calendly-Inspired Phishing Attack Aims to Steal Google Workspace Credentials
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
  - Source: https://gbhackers.com/calendly-inspired-phishing/

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
  - IOCs: --
  - Source: https://gbhackers.com/phishing-attack-2/

Entry 10
- [10] Threat Actors Using Matanbuchus Downloader to Deliver Ransomware and Maintain Persistence
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1053.005 — Scheduled Task 
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
    - T1588.006: Pre-compromise 
    - T1218.007: Disable or Remove Feature or Program 
    - T1036: Audit 
    - T1059.001: Disable or Remove Feature or Program
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - filename: HRUpdate.exe, msiexec.exe
    - malware: APPDATA, SHA256
    - hash: 92a2e2a124a106af33993828fb0d4cdffd9dac8790169774d672c30747769455, 6246801035e053df2053b2dc28f4e76e3595fb62fdd02b5a50d9a2ed3796b153, 3ac90c071d143c3240974618d395fa3c5228904c8bf0a89a49f8c01cd7777421, 77a53dc757fdf381d3906ab256b74ad3cdb7628261c58a62bcc9c6ca605307ba
    - domain: even.net
  - Source: https://gbhackers.com/matanbuchus-downloader/

Entry 11
- [11] Deep dive into DragonForce ransomware and its Scattered Spider connection
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
    - domain: truesight.sys, rentdrv2.sys
  - Source: https://www.bleepingcomputer.com/news/security/deep-dive-into-dragonforce-ransomware-and-its-scattered-spider-connection/

Entry 12
- [12] FTC settlement requires Illuminate to delete unnecessary student data
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
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/ftc-settlement-requires-illuminate-to-delete-unnecessary-student-data/

Entry 13
- [13] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, zero day, cloud
  - IOCs:
    - filename: of.lnk, an.lnk
  - Source: https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html

Entry 14
- [14] WordPress King Addons Flaw Under Active Attack Lets Hackers Make Admin Accounts
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs:
    - ip: 182.8.226.228, 138.199.21.230, 206.238.221.25
    - domain: ajax.php
  - Source: https://thehackernews.com/2025/12/wordpress-king-addons-flaw-under-active.html

Entry 15
- [15] Brazil Hit by Banking Trojan Spread via WhatsApp Worm and RelayNFC NFC Relay Fraud
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1047 — Windows Management Instrumentation 
    - T1113 — Screen Capture 
    - T1093 — Process Hollowing 
    - T1588.006 — Vulnerabilities 
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
    - T1047: Privileged Account Management 
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit
  - Enablers: ai, artificial intelligence, cryptocurrency
  - IOCs:
    - filename: svchost.exe
    - domain: executed.dat, test.ikotech
  - Source: https://thehackernews.com/2025/12/brazil-hit-by-banking-trojan-spread-via.html

Entry 16
- [16] Shai-Hulud 2.0 NPM malware attack exposed up to 400,000 dev secrets
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1589.001 — Credentials 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1589.001: Pre-compromise 
    - T1190: Application Isolation and Sandboxing 
    - T1059: Limit Software Installation
  - Enablers: ai, cloud, aws
  - IOCs:
    - software_package: agent@0.6.7, @asyncapi/specs@6.8.3
    - filename: contents.json, trufflesecrets.json, environment.json, actionssecrets.json
  - Source: https://www.bleepingcomputer.com/news/security/shai-hulud-20-npm-malware-attack-exposed-up-to-400-000-dev-secrets/

Entry 17
- [17] Cybercrime Goes SaaS: Renting Tools, Access, and Infrastructure
  - Category: Phishing
  - Relevance: Critical (100)
  - Actionability: Medium (57)
  - MITRE Techniques:
    - T1586.002 — Email Accounts 
    - T1505.003 — Web Shell 
    - T1021.007 — Cloud Services 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials
  - Mitigations:
    - T1586.002: Pre-compromise 
    - T1505.003: Disable or Remove Feature or Program 
    - T1021.007: Multi-factor Authentication 
    - T1566: Audit 
    - T1587.004: Pre-compromise
  - Enablers: ai, cloud, phishing
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/cybercrime-goes-saas-renting-tools-access-and-infrastructure/

Entry 18
- [18] North Korea lures engineers to rent identities in fake IT worker scheme
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1090 — Proxy 
    - T1587.004 — Exploits 
    - T1059.006 — Python 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise 
    - T1090: Filter Network Traffic 
    - T1587.004: Pre-compromise
  - Enablers: ai
  - IOCs:
    - malware: CAPTCHA
    - domain: any.run
  - Source: https://www.bleepingcomputer.com/news/security/north-korea-lures-engineers-to-rent-identities-in-fake-it-worker-scheme/

Entry 19
- [19] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, artificial intelligence, cloud
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/discover-ai-tools-fueling-next.html

Entry 20
- [20] Chopping AI Down to Size: Turning Disruptive Technology into a Strategic Advantage
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1059.006 — Python
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise 
    - T1059.006: Audit
  - Enablers: ai, artificial intelligence, machine learning
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/chopping-ai-down-to-size-turning.html

Entry 21
- [21] Researchers Capture Lazarus APT's Remote-Worker Scheme Live on Camera
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1090 — Proxy 
    - T1021.007 — Cloud Services 
    - T1059.001 — PowerShell 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1555.003 — Credentials from Web Browsers
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1090: Filter Network Traffic 
    - T1021.007: Multi-factor Authentication 
    - T1059.001: Disable or Remove Feature or Program 
    - T1587.004: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs:
    - domain: any.run, otp.ee, authenticator.cc
  - Source: https://thehackernews.com/2025/12/researchers-capture-lazarus-apts-remote.html

Entry 22
- [22] Malicious Rust Crate Delivers OS-Specific Malware to Web3 Developer Systems
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (20)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1036 — Masquerading 
    - T1021.007 — Cloud Services 
    - T1059.001 — PowerShell 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1059.005 — Visual Basic
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1036: Audit 
    - T1021.007: Multi-factor Authentication 
    - T1059.001: Disable or Remove Feature or Program 
    - T1592.002: Pre-compromise
  - Enablers: ai, cryptocurrency, cloud
  - IOCs:
    - filename: qhsafetray.exe
    - domain: crates.io, download.videotalks
  - Source: https://thehackernews.com/2025/12/malicious-rust-crate-delivers-os.html

Entry 23
- [23] India Orders Messaging Apps to Work Only With Active SIM Cards to Prevent Fraud and Misuse
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1102 — Web Service 
    - T1021.007 — Cloud Services 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1656 — Impersonation
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1102: Network Intrusion Prevention 
    - T1021.007: Multi-factor Authentication 
    - T1566: Audit 
    - T1587.004: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/india-orders-messaging-apps-to-work.html

Entry 24
- [24] Picklescan Bugs Allow Malicious PyTorch Models to Evade Scans and Execute Code
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
    - domain: as.bin, or.pt, linecache.getline
  - Source: https://thehackernews.com/2025/12/picklescan-bugs-allow-malicious-pytorch.html

Entry 25
- [25] GlassWorm Returns with 24 Malicious Extensions Impersonating Popular Developer Tools
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cryptocurrency, cloud
  - IOCs:
    - domain: iconkieftwo.icon, inc.prisma, vsc.vsce, flutcode.flutter, csvmech.csvrainbow, codevsce.codelddb, saoudrizvsce.claude, clangdcode.clangd, cweijamysq.sync, bphpburnsus.iconesvscode
  - Source: https://thehackernews.com/2025/12/glassworm-returns-with-24-malicious.html

Entry 26
- [26] Malicious npm Package Uses Hidden Prompt and Script to Evade AI Security Tools
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1595.002 — Vulnerability Scanning 
    - T1204.005 — Malicious Library 
    - T1021.007 — Cloud Services 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1595.002: Pre-compromise 
    - T1204.005: Limit Software Installation 
    - T1021.007: Multi-factor Authentication 
    - T1566: Audit
  - Enablers: ai, artificial intelligence, cloud
  - IOCs:
    - software_package: uses-hidden-prompt-and-script-to-evade-ai-security-tools-malicious-npm-package-uses-hidden-prompt-and-script-to-evade-ai-security-tools
  - Source: https://thehackernews.com/2025/12/malicious-npm-package-uses-hidden.html

Entry 27
- [27] SecAlerts Cuts Through the Noise with a Smarter, Faster Way to Track Vulnerabilities
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/secalerts-cuts-through-noise-with.html

Entry 28
- [28] Iran-Linked Hackers Hit Israeli Sectors with New MuddyViper Backdoor in Targeted Attacks
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1566.001 — Spearphishing Attachment 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit 
    - T1587.004: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs:
    - malware: POWERSTATS
  - Source: https://thehackernews.com/2025/12/iran-linked-hackers-hits-israeli_2.html

Entry 29
- [29] Google Patches 107 Android Flaws, Including Two Framework Bugs Exploited in the Wild
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/google-patches-107-android-flaws.html

Entry 30
- [30] [webapps] phpMyFAQ  2.9.8 - Cross-Site Request Forgery (CSRF)
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
    - domain: github.com, index.php, document.forms, glossary.main.php, glossary.edit.php
  - Source: https://www.exploit-db.com/exploits/52458

Entry 31
- [31] [webapps] phpMyFAQ 2.9.8 - Cross-Site Request Forgery(CSRF)
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
    - domain: github.com, index.php, stat.main.php, document.forms
  - Source: https://www.exploit-db.com/exploits/52459

Entry 32
- [32] [webapps] MaNGOSWebV4  4.0.6 - Reflected XSS
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
    - domain: github.com, index.php
  - Source: https://www.exploit-db.com/exploits/52457

Entry 33
- [33] [webapps] Django 5.1.13 - SQL Injection
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

Entry 34
- [34] [webapps] phpMyFaq 2.9.8 - Cross Site Request Forgery (CSRF)
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
    - domain: github.com, index.php, example.com, document.forms, poc.html
  - Source: https://www.exploit-db.com/exploits/52455

Entry 35
- [35] [webapps] MobileDetect 2.8.31 - Cross-Site Scripting (XSS)
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

Entry 36
- [36] [webapps] phpIPAM 1.4 - SQL-Injection
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
    - domain: github.com, order.php
  - Source: https://www.exploit-db.com/exploits/52453

Entry 37
- [37] [webapps] OpenRepeater 2.1 - OS Command Injection
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

Entry 38
- [38] [webapps] phpMyAdmin 5.0.0 - SQL Injection
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

Entry 39
- [39] [webapps] RosarioSIS 6.7.2 - Cross Site Scripting (XSS)
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
    - domain: gitlab.com, modules.php, preferences.php, warehous.php
  - Source: https://www.exploit-db.com/exploits/52450

Entry 40
- [40] [webapps] openSIS Community Edition 8.0 - SQL Injection
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
    - domain: github.com, forgotpassusername.php
  - Source: https://www.exploit-db.com/exploits/52447

Entry 41
- [41] [webapps] PluckCMS 4.7.10 - Unrestricted File Upload
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
    - domain: github.com, admin.php, exploit.php.jpg
  - Source: https://www.exploit-db.com/exploits/52448

Entry 42
- [42] [webapps] RosarioSIS 6.7.2 - Cross-Site Scripting (XSS)
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
    - domain: gitlab.com, modules.php, printschedules.php
  - Source: https://www.exploit-db.com/exploits/52449

Entry 43
- [43] [webapps] YOURLS 1.8.2 - Cross-Site Request Forgery (CSRF)
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
    - malware: YOURLS, DOCTYPE
    - url: https://github.com/yourls/yourls/, http://yourls/admin/index.php
    - domain: github.com, index.php, document.forms, poc.html
  - Source: https://www.exploit-db.com/exploits/52446

Entry 44
- [44] [webapps] phpMyFAQ  3.1.7 - Reflected Cross-Site Scripting (XSS)
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
    - url: https://github.com/thorsten/phpmyfaq/, http://phpmyfaq1/index.php?action=main&search=%22%20onfocus%3d%22alert%281%29
    - domain: github.com, index.php
  - Source: https://www.exploit-db.com/exploits/52445

Entry 45
- [45] [webapps] phpIPAM 1.5.1 - SQL Injection
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
    - malware: PHPSESSID, SELECT
    - url: https://github.com/phpipam/phpipam/
    - domain: github.com, result.php
  - Source: https://www.exploit-db.com/exploits/52444

Entry 46
- [46] [webapps] phpIPAM 1.6 - Reflected-Cross-Site Scripting (XSS)
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
    - url: https://github.com/phpipam/phpipam/
    - domain: github.com, edit.php
  - Source: https://www.exploit-db.com/exploits/52442

Entry 47
- [47] [webapps] Piwigo 13.6.0 - SQL Injection
  - Category: Injection
  - Relevance: Critical (100)
  - Actionability: Medium (58)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.006: User Training 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - url: https://github.com/piwigo/piwigo
    - domain: github.com, admin.php
  - Source: https://www.exploit-db.com/exploits/52443

Entry 48
- [48] [webapps] phpIPAM 1.6 - Reflected Cross-Site Scripting (XSS)
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
    - url: https://github.com/phpipam/phpipam/, http://phpipam/app/admin/import
    - domain: github.com, preview.php
  - Source: https://www.exploit-db.com/exploits/52441

Entry 49
- [49] ZDI-CAN-28260: Microsoft
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1592.002 — Software 
    - T1059.006 — Python
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1592.002: Pre-compromise 
    - T1059.006: Audit
  - Enablers: ai, zero day, aws
  - IOCs:
    - malware: ZDI-CAN-28260, UPCOMING, PUBLISHED, ADVISORIES, AFFECTED, VENDOR, SEVERITY, REPORTED, DEADLINE, DISCOVERER
  - Source: http://www.zerodayinitiative.com/advisories/upcoming/

Entry 50
- [50] Aisuru botnet behind new record-breaking 29.7 Tbps DDoS attack
  - Category: DDoS/Botnet
  - Relevance: Critical (95)
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
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/aisuru-botnet-behind-new-record-breaking-297-tbps-ddos-attack/

Entry 51
- [51] Korea arrests suspects selling intimate videos from hacked IP cameras
  - Category: Other
  - Relevance: High (78)
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1557.004 — Evil Twin 
    - T1592.003 — Firmware
  - Mitigations:
    - T1557.004: Network Intrusion Prevention 
    - T1592.003: Pre-compromise
  - Enablers: ai
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/korea-arrests-suspects-selling-intimate-videos-from-hacked-ip-cameras/

Entry 52
- [52] Microsoft "mitigates" Windows LNK flaw exploited as zero-day
  - Category: Phishing
  - Relevance: High (76)
  - Actionability: High (67)
  - MITRE Techniques:
    - T1553.005 — Mark-of-the-Web Bypass 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1553.005: Disable or Remove Feature or Program 
    - T1566.001: Antivirus/Antimalware
  - Enablers: ai, zero-day, zero day
  - IOCs:
    - filename: block.lnk, handles.lnk, windows.lnk
  - Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-mitigates-windows-lnk-flaw-exploited-as-zero-day/

Entry 53
- [53] University of Phoenix discloses data breach after Oracle hack
  - Category: Other
  - Relevance: Medium (55)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1566 — Phishing
  - Mitigations:
    - T1566: Audit
  - Enablers: ai, zero day, phishing
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/university-of-phoenix-discloses-data-breach-after-oracle-hack/

Entry 54
- [54] Microsoft Defender portal outage disrupts threat hunting alerts
  - Category: Phishing
  - Relevance: Medium (55)
  - Actionability: Informational (22)
  - MITRE Techniques:
    - T1667 — Email Bombing
  - Mitigations:
    - T1667: User Training
  - Enablers: ai, phishing
  - IOCs:
    - malware: DZ1191468
  - Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-portal-outage-blocks-access-to-security-alerts/

Entry 55
- [55] ZDI-25-1039: (Pwn2Own) Synology BeeStation Plus auth_info Stack-based Buffer Overflow Remote Code Execution Vulnerability
  - Category: Remote Code Execution
  - Relevance: Medium (40)
  - Actionability: High (70)
  - Mitigations: --
  - Enablers: zero day
  - IOCs:
    - malware: ZDI-25-1039, AFFECTED, VENDORS, PRODUCTS, VULNERABILITY, DETAILS, ADDITIONAL, DISCLOSURE, TIMELINE, CREDIT
  - Source: http://www.zerodayinitiative.com/advisories/ZDI-25-1039/

Entry 56
- [56] ZDI-25-1040: (Pwn2Own) Synology DiskStation DS925+ samlAuth Authentication Bypass Vulnerability
  - Category: Other
  - Relevance: Medium (40)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: zero day
  - IOCs:
    - malware: ZDI-25-1040, AFFECTED, VENDORS, PRODUCTS, VULNERABILITY, DETAILS, SYNOPAMSSO, ADDITIONAL, DISCLOSURE, TIMELINE
  - Source: http://www.zerodayinitiative.com/advisories/ZDI-25-1040/

Entry 57
- [57] Google expands Android scam protection feature to Chase, Cash App in U.S.
  - Category: Other
  - Relevance: Medium (30)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: ai
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/google-expands-android-scam-protection-feature-to-chase-cash-app-in-us/

Entry 58
- [58] Russia blocks Roblox over distribution of LGBT "propaganda"
  - Category: Ransomware
  - Relevance: Low (28)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: ai, zero day
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/russia-blocks-roblox-over-distribution-of-lgbt-propaganda/

Entry 59
- [59] NCSC-2025-0379 [1.00] [M/H] Kwetsbaarheden verholpen in Google Android en Samsung Mobile
  - Category: Other
  - Relevance: Low (22)
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - malware: NCSC-2025-0379
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0379

Entry 60
- [60] ChatGPT is down worldwide, conversations disappeared for users
  - Category: Other
  - Relevance: Low (20)
  - Actionability: Informational (20)
  - Mitigations: --
  - Enablers: ai, artificial intelligence
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/artificial-intelligence/chatgpt-is-down-worldwide-conversations-disappeared-for-users/