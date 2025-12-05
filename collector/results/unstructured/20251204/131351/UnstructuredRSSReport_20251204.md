## Summary

- Total findings: 27



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 2
**Data Completeness:** 92% (25/27 entries have threats+actors+MITRE)

Entry 1
- [1] Hackers Weaponize Velociraptor DFIR for Stealthy C2 and Ransomware Deployment
  - Category: Data Theft
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
  - IOCs:
    - filename: code.exe, toolpane.aspx, signout.aspx, start.aspx
    - malware: SYSTEM, DESKTOP
    - domain: bf05.qgtxtebl.workers, next.js, update.githubtestbak.workers.dev, bf05.qgtxtebl.workers.dev
  - Source: https://gbhackers.com/velociraptor-dfir/

Entry 2
- [2] Akamai Fixes HTTP Request Smuggling Flaw in Edge Servers
  - Category: Remote Code Execution
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
  - IOCs:
    - domain: next.js
  - Source: https://gbhackers.com/akamai-fixes-http-request-smuggling-flaw/

Entry 3
- [3] PickleScan Uncovers 0-Day Vulnerabilities Allowing Arbitrary Code Execution via Malicious PyTorch Models
  - Category: Data Theft
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
  - Enablers: phishing
  - IOCs:
    - domain: like.bin, or.pt, next.js
  - Source: https://gbhackers.com/picklescan-0-day/

Entry 4
- [4] New Scanner Released to Detect Exposed ReactJS and Next.js RSC Endpoints (CVE-2025-55182)
  - Category: Remote Code Execution
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
  - IOCs:
    - url: http://localhost
    - domain: next.js, runtime.js
  - Source: https://gbhackers.com/new-scanner-released-to-detect-exposed-reactjs-and-next-js-rsc-endpoints/

Entry 5
- [5] Vim for Windows Flaw Lets Attackers Execute Arbitrary Code
  - Category: Remote Code Execution
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
  - IOCs:
    - filename: findstr.exe
    - domain: next.js
  - Source: https://gbhackers.com/vim-for-windows-flaw/

Entry 6
- [6] Marquis Data Breach Exposes Dozens of U.S. Banks and Credit Unions
  - Category: Remote Code Execution
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
  - IOCs:
    - domain: next.js
  - Source: https://gbhackers.com/marquis-data-breach-exposes-dozens-of-u-s-banks/

Entry 7
- [7] Sryxen Malware Uses Headless Browser Trick to Bypass Chrome Protections
  - Category: Data Theft
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
  - Enablers: phishing
  - IOCs:
    - malware: KUSER_SHARED_DATA
    - filename: logins.json
    - domain: api.telegram.org, next.js
  - Source: https://gbhackers.com/sryxen-malware/

Entry 8
- [8] WordPress Plugin Vulnerability Under Active Attack, Allowing Remote Code Execution
  - Category: Remote Code Execution
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
  - IOCs:
    - ip: 185.125.50.59
    - domain: next.js
  - Source: https://gbhackers.com/wordpress-plugin-2/

Entry 9
- [9] Contractors with hacking records accused of wiping 96 govt databases
  - Category: Ransomware
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1213.006 — Databases
  - Mitigations:
    - T1213.006: User Training
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/contractors-with-hacking-records-accused-of-wiping-96-govt-databases/

Entry 10
- [10] K7 Antivirus Flaw Lets Attackers Gain SYSTEM-Level Privileges
  - Category: Remote Code Execution
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
  - IOCs:
    - malware: SYSTEM
    - domain: next.js
  - Source: https://gbhackers.com/k7-antivirus-flaw/

Entry 11
- [11] Marquis data breach impacts over 74 US banks, credit unions
  - Category: Remote Code Execution
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
  - IOCs:
    - malware: IBERIABANK
    - ip: 12.03.25.1
    - domain: bleepingcomputer.com
  - Source: https://www.bleepingcomputer.com/news/security/marquis-data-breach-impacts-over-74-us-banks-credit-unions/

Entry 12
- [12] Microsoft 365 license check bug blocks desktop app downloads
  - Category: Other
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1053.005 — Scheduled Task 
    - T1667 — Email Bombing 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1053.005: Privileged Account Management 
    - T1667: User Training 
    - T1566.001: Antivirus/Antimalware
  - IOCs:
    - malware: OP1192004
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-bug-in-microsoft-365-license-checks-blocks-desktop-app-downloads/

Entry 13
- [13] CISA Issues Five New ICS Advisories on Emerging Vulnerabilities and Exploits
  - Category: Other
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
  - IOCs:
    - malware: SYSTEM, MELSEC
    - domain: next.js
  - Source: https://gbhackers.com/five-new-ics-advisories/

Entry 14
- [14] How strong password policies secure OT systems against cyber threats
  - Category: Remote Code Execution
  - Actionability: High (60)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1110 — Brute Force 
    - T1556.006 — Multi-Factor Authentication 
    - T1592.002 — Software 
    - T1589.001 — Credentials
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1110: User Account Management 
    - T1556.006: User Account Management 
    - T1592.002: Pre-compromise 
    - T1589.001: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/how-strong-password-policies-secure-ot-systems-against-cyber-threats/

Entry 15
- [15] Critical React, Next.js flaw lets hackers execute code on servers
  - Category: Remote Code Execution
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
    - domain: next.js
  - Source: https://www.bleepingcomputer.com/news/security/critical-react2shell-flaw-in-react-nextjs-lets-hackers-run-javascript-code/

Entry 16
- [16] Critical flaw in WordPress add-on for Elementor exploited in attacks
  - Category: Remote Code Execution
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1590.005 — IP Addresses
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1590.005: Pre-compromise
  - IOCs:
    - ip: 2602:fa59:3:424::1, 45.61.157.120, 0.9.0.5, 0.9.1.1, 12.03.25.1
    - filename: ajax.php
  - Source: https://www.bleepingcomputer.com/news/security/critical-flaw-in-wordpress-add-on-for-elementor-exploited-in-attacks/

Entry 17
- [17] French DIY retail giant Leroy Merlin discloses a data breach
  - Category: Privilege Escalation
  - Actionability: Medium (40)
  - MITRE Techniques:
    - T1566 — Phishing 
    - T1593.001 — Social Media
  - Mitigations:
    - T1566: Audit 
    - T1593.001: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/french-diy-retail-giant-leroy-merlin-discloses-a-data-breach/

Entry 18
- [18] 5 Threats That Reshaped Web Security This Year [2025]
  - Category: Data Theft
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
  - IOCs:
    - domain: polyfill.io, web3.js, analytics.com
  - Source: https://thehackernews.com/2025/12/5-threats-that-reshaped-web-security.html

Entry 19
- [19] Freedom Mobile discloses data breach exposing customer data
  - Category: Data Theft
  - Actionability: Medium (52)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1566.001: Antivirus/Antimalware
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/freedom-mobile-discloses-data-breach-exposing-customer-data/

Entry 20
- [20] ThreatsDay Bulletin: Wi-Fi Hack, npm Worm, DeFi Theft, Phishing Blasts— and 15 More Stories
  - Category: Data Theft
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1053.005 — Scheduled Task 
    - T1557 — Adversary-in-the-Middle 
    - T1583.001 — Domains 
    - T1557.004 — Evil Twin 
    - T1589.002 — Email Addresses 
    - T1021.007 — Cloud Services 
    - T1583.006 — Web Services 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1027.003 — Steganography 
    - T1059.006 — Python 
    - T1059.005 — Visual Basic 
    - T1027.015 — Compression 
    - T1566.001 — Spearphishing Attachment 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1053.005: Privileged Account Management 
    - T1557: Filter Network Traffic 
    - T1583.001: Pre-compromise 
    - T1557.004: Network Intrusion Prevention 
    - T1589.002: Pre-compromise
  - Enablers: phishing
  - IOCs:
    - malware: CAPTCHA, COLDRIVER, STONESTOP, ABYSSWORKER, LAPSUS
    - email: mostafa.s@dhic.edu
    - domain: hunt.io, lokibot.net, a.net, dhic.edu
  - Source: https://thehackernews.com/2025/12/threatsday-bulletin-wi-fi-hack-npm-worm.html

Entry 21
- [21] Russia blocks Roblox over distribution of LGBT "propaganda"
  - Category: Ransomware
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: zero day
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/russia-blocks-roblox-over-distribution-of-lgbt-propaganda/

Entry 22
- [22] Critical RSC Bugs in React and Next.js Allow Unauthenticated Remote Code Execution
  - Category: Other
  - Actionability: Medium (45)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1021.007 — Cloud Services 
    - T1583.006 — Web Services 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1021.007: Multi-factor Authentication 
    - T1583.006: Pre-compromise 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - domain: next.js, vm.runinthiscontext, node.js
  - Source: https://thehackernews.com/2025/12/critical-rsc-bugs-in-react-and-nextjs.html

Entry 23
- [23] NCSC-2025-0380 [1.00] [H/H] Kwetsbaarheden verholpen in React Server Components
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0380

Entry 24
- [24] Record 29.7 Tbps DDoS Attack Linked to AISURU Botnet with up to 4 Million Infected Hosts
  - Category: Other
  - Actionability: Informational (24)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - Countries: Vietnam (Target)
  - IOCs:
    - malware: AISURU
  - Source: https://thehackernews.com/2025/12/record-297-tbps-ddos-attack-linked-to.html

Entry 25
- [25] GoldFactory Hits Southeast Asia with Modified Banking Apps Driving 11,000+ Infections
  - Category: Other
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
  - Countries: Vietnam (Target)
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/goldfactory-hits-southeast-asia-with.html

Entry 26
- [26] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
  - Category: Other
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
  - Enablers: ai
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/discover-ai-tools-fueling-next.html

Entry 27
- [27] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
  - Category: Other
  - Actionability: Medium (55)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - IOCs:
    - filename: of.lnk, an.lnk
  - Source: https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html