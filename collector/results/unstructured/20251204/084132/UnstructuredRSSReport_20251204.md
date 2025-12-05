## Summary

- Total findings: 29



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 4
**Data Completeness:** 86% (25/29 entries have threats+actors+MITRE)

Entry 1
- [1] Akamai Fixes HTTP Request Smuggling Flaw in Edge Servers
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 1.1.6.1
    - domain: next.js
  - Source: https://gbhackers.com/akamai-fixes-http-request-smuggling-flaw/

Entry 2
- [2] Sryxen Malware Uses Headless Browser Trick to Bypass Chrome Protections
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Medium (32)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1555.001 — Keychain 
    - T1213.006 — Databases 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1059.001 — PowerShell 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1027.015 — Compression 
    - T1555.003 — Credentials from Web Browsers 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1555.001: Password Policies 
    - T1213.006: User Training 
    - T1588.006: Pre-compromise 
    - T1059.001: Disable or Remove Feature or Program
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - malware: KUSER_SHARED_DATA
    - ip: 1.1.6.1
    - filename: logins.json
    - domain: api.telegram.org, next.js
  - Source: https://gbhackers.com/sryxen-malware/

Entry 3
- [3] PickleScan Uncovers 0-Day Vulnerabilities Allowing Arbitrary Code Execution via Malicious PyTorch Models
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1059.006 — Python 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1059.006: Audit 
    - T1041: Network Intrusion Prevention
  - Enablers: ai, artificial intelligence, machine learning
  - IOCs:
    - ip: 1.1.6.1
    - domain: like.bin, or.pt, next.js
  - Source: https://gbhackers.com/picklescan-0-day/

Entry 4
- [4] Marquis data breach impacts over 74 US banks, credit unions
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: High (65)
  - MITRE Techniques:
    - T1556.006 — Multi-Factor Authentication 
    - T1592.002 — Software 
    - T1589.001 — Credentials 
    - T1078.003 — Local Accounts 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1556.006: User Account Management 
    - T1592.002: Pre-compromise 
    - T1589.001: Pre-compromise 
    - T1078.003: Privileged Account Management 
    - T1041: Network Intrusion Prevention
  - Enablers: ai, mfa
  - IOCs:
    - malware: IBERIABANK
    - ip: 12.03.25.1
    - domain: bleepingcomputer.com
  - Source: https://www.bleepingcomputer.com/news/security/marquis-data-breach-impacts-over-74-us-banks-credit-unions/

Entry 5
- [5] Marquis Data Breach Exposes Dozens of U.S. Banks and Credit Unions
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (45)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1588.006: Pre-compromise 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 1.1.6.1
    - domain: next.js
  - Source: https://gbhackers.com/marquis-data-breach-exposes-dozens-of-u-s-banks/

Entry 6
- [6] New Scanner Released to Detect Exposed ReactJS and Next.js RSC Endpoints (CVE-2025-55182)
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1588.006 — Vulnerabilities 
    - T1595.002 — Vulnerability Scanning 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1059.006 — Python 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1588.006: Pre-compromise 
    - T1595.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1059.006: Audit
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 1.1.6.1
    - url: http://localhost
    - domain: next.js, runtime.js
  - Source: https://gbhackers.com/new-scanner-released-to-detect-exposed-reactjs-and-next-js-rsc-endpoints/

Entry 7
- [7] Hackers Weaponize Velociraptor DFIR for Stealthy C2 and Ransomware Deployment
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1204.002 — User Execution: Malicious File 
    - T1190 — Exploit Public-Facing Application 
    - T1213.002 — Sharepoint 
    - T1543.003 — Windows Service 
    - T1588.006 — Vulnerabilities 
    - T1218.007 — Msiexec 
    - T1505.003 — Web Shell 
    - T1064 — Scripting 
    - T1021.007 — Cloud Services 
    - T1059.001 — PowerShell 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1204.002: Execution Prevention 
    - T1190: Application Isolation and Sandboxing 
    - T1213.002: Audit 
    - T1543.003: Behavior Prevention on Endpoint 
    - T1588.006: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - filename: code.exe, toolpane.aspx, signout.aspx, start.aspx
    - malware: SYSTEM, DESKTOP
    - ip: 1.1.6.1
    - domain: bf05.qgtxtebl.workers, next.js, update.githubtestbak.workers.dev
  - Source: https://gbhackers.com/velociraptor-dfir/

Entry 8
- [8] Freedom Mobile discloses data breach exposing customer data
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Medium (52)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1566.001: Antivirus/Antimalware
  - Enablers: ai
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/freedom-mobile-discloses-data-breach-exposing-customer-data/

Entry 9
- [9] Deep dive into DragonForce ransomware and its Scattered Spider connection
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
    - ip: 12.03.25.1
    - domain: truesight.sys, rentdrv2.sys
  - Source: https://www.bleepingcomputer.com/news/security/deep-dive-into-dragonforce-ransomware-and-its-scattered-spider-connection/

Entry 10
- [10] Microsoft "mitigates" Windows LNK flaw exploited as zero-day
  - Category: Phishing
  - Relevance: Critical (100)
  - Actionability: High (67)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1553.005 — Mark-of-the-Web Bypass 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1553.005: Disable or Remove Feature or Program 
    - T1566.001: Antivirus/Antimalware
  - Enablers: ai, zero-day, zero day
  - IOCs:
    - ip: 12.03.25.1
    - filename: block.lnk, handles.lnk, windows.lnk
  - Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-mitigates-windows-lnk-flaw-exploited-as-zero-day/

Entry 11
- [11] 5 Threats That Reshaped Web Security This Year [2025]
  - Category: Data Theft
  - Relevance: Critical (100)
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
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
    - T1583.001: Pre-compromise 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise
  - Enablers: ai, cryptocurrency, cloud
  - IOCs:
    - domain: polyfill.io, web3.js, analytics.com
  - Source: https://thehackernews.com/2025/12/5-threats-that-reshaped-web-security.html

Entry 12
- [12] GoldFactory Hits Southeast Asia with Modified Banking Apps Driving 11,000+ Infections
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1056.001 — Keylogging 
    - T1179 — Hooking 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1656 — Impersonation
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise 
    - T1656: User Training
  - Enablers: ai, cloud, aws
  - Countries: Vietnam (Target)
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/goldfactory-hits-southeast-asia-with.html

Entry 13
- [13] Critical RSC Bugs in React and Next.js Allow Unauthenticated Remote Code Execution
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Medium (45)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1021.007 — Cloud Services 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1021.007: Multi-factor Authentication 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, cloud, aws
  - IOCs:
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/critical-rsc-bugs-in-react-and-nextjs.html

Entry 14
- [14] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
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
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/discover-ai-tools-fueling-next.html

Entry 15
- [15] WordPress King Addons Flaw Under Active Attack Lets Hackers Make Admin Accounts
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
    - ip: 2602:fa59:3:424::1, 45.61.157.120, 182.8.226.228, 138.199.21.230, 206.238.221.25
    - filename: ajax.php
  - Source: https://thehackernews.com/2025/12/wordpress-king-addons-flaw-under-active.html

Entry 16
- [16] Brazil Hit by Banking Trojan Spread via WhatsApp Worm and RelayNFC NFC Relay Fraud
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
    - domain: executed.dat, test.ikotech, manoelimoveiscaioba.com, serverseistemasatu.com, maisseguraca.site, test.ikotech.online
  - Source: https://thehackernews.com/2025/12/brazil-hit-by-banking-trojan-spread-via.html

Entry 17
- [17] WordPress Plugin Vulnerability Under Active Attack, Allowing Remote Code Execution
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: High (60)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - ip: 185.125.50.59, 1.1.6.1
    - domain: next.js
  - Source: https://gbhackers.com/wordpress-plugin-2/

Entry 18
- [18] CISA Issues Five New ICS Advisories on Emerging Vulnerabilities and Exploits
  - Category: Other
  - Relevance: Critical (100)
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1116 — Code Signing 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1592.003 — Firmware 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1588.006: Pre-compromise 
    - T1592.003: Pre-compromise 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - malware: SYSTEM, MELSEC
    - ip: 1.1.6.1
    - domain: next.js
  - Source: https://gbhackers.com/five-new-ics-advisories/

Entry 19
- [19] K7 Antivirus Flaw Lets Attackers Gain SYSTEM-Level Privileges
  - Category: Remote Code Execution
  - Relevance: Critical (100)
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1559 — Inter-Process Communication 
    - T1592.002 — Software 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1588.006: Pre-compromise 
    - T1559: Disable or Remove Feature or Program 
    - T1592.002: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - Enablers: ai, artificial intelligence, zero day
  - IOCs:
    - malware: SYSTEM
    - ip: 1.1.6.1
    - domain: next.js
  - Source: https://gbhackers.com/k7-antivirus-flaw/

Entry 20
- [20] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
  - Category: Other
  - Relevance: Critical (99)
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
    - filename: of.lnk, an.lnk
  - Source: https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html

Entry 21
- [21] French DIY retail giant Leroy Merlin discloses a data breach
  - Category: Privilege Escalation
  - Relevance: Critical (98)
  - Actionability: Medium (40)
  - MITRE Techniques:
    - T1566 — Phishing 
    - T1593.001 — Social Media
  - Mitigations:
    - T1566: Audit 
    - T1593.001: Pre-compromise
  - Enablers: ai, phishing
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/french-diy-retail-giant-leroy-merlin-discloses-a-data-breach/

Entry 22
- [22] Aisuru botnet behind new record-breaking 29.7 Tbps DDoS attack
  - Category: DDoS/Botnet
  - Relevance: Critical (97)
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
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/aisuru-botnet-behind-new-record-breaking-297-tbps-ddos-attack/

Entry 23
- [23] Record 29.7 Tbps DDoS Attack Linked to AISURU Botnet with up to 4 Million Infected Hosts
  - Category: Other
  - Relevance: Critical (97)
  - Actionability: Informational (24)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Enablers: ai, artificial intelligence, cloud
  - Countries: Vietnam (Target)
  - IOCs:
    - malware: AISURU
  - Source: https://thehackernews.com/2025/12/record-297-tbps-ddos-attack-linked-to.html

Entry 24
- [24] Critical flaw in WordPress add-on for Elementor exploited in attacks
  - Category: Remote Code Execution
  - Relevance: Critical (90)
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1590.005 — IP Addresses
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1590.005: Pre-compromise
  - Enablers: ai
  - IOCs:
    - ip: 2602:fa59:3:424::1, 45.61.157.120, 0.9.0.5, 0.9.1.1, 12.03.25.1
    - filename: ajax.php
  - Source: https://www.bleepingcomputer.com/news/security/critical-flaw-in-wordpress-add-on-for-elementor-exploited-in-attacks/

Entry 25
- [25] University of Phoenix discloses data breach after Oracle hack
  - Category: Other
  - Relevance: Medium (57)
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1566 — Phishing
  - Mitigations:
    - T1566: Audit
  - Enablers: ai, zero day, phishing
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/university-of-phoenix-discloses-data-breach-after-oracle-hack/

Entry 26
- [26] Google expands Android scam protection feature to Chase, Cash App in U.S.
  - Category: Other
  - Relevance: Medium (48)
  - Actionability: Critical (95)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/google-expands-android-scam-protection-feature-to-chase-cash-app-in-us/

Entry 27
- [27] Russia blocks Roblox over distribution of LGBT "propaganda"
  - Category: Ransomware
  - Relevance: Medium (30)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: ai, zero day
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/russia-blocks-roblox-over-distribution-of-lgbt-propaganda/

Entry 28
- [28] NCSC-2025-0380 [1.00] [H/H] Kwetsbaarheden verholpen in React Server Components
  - Category: Other
  - Relevance: Low (20)
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0380

Entry 29
- [29] Vim for Windows Flaw Lets Attackers Execute Arbitrary Code
  - Category: Other
  - Relevance: Low (20)
  - Actionability: Informational (15)
  - Mitigations: --
  - IOCs: --
  - Source: https://gbhackers.com/vim-for-windows-flaw/