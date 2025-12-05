## Summary

- Total findings: 34



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 2
**Data Completeness:** 94% (32/34 entries have threats+actors+MITRE)

Entry 1
- [1] Longwatch RCE Flaw Allows Attackers to Run Remote Code with Elevated Privileges
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

Entry 2
- [2] Shai-Hulud 2.0 Cyberattack Compromises 30,000 Repos and Exposes 500 GitHub Accounts
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

Entry 3
- [3] Malicious Rust “evm-units” Impersonator Deploys OS-Specific Payloads
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

Entry 4
- [4] New Calendly-Inspired Phishing Attack Aims to Steal Google Workspace Credentials
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

Entry 5
- [5] Let’s Encrypt Cutting Certificate Lifespan from 90 Days to 45 Days
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

Entry 6
- [6] Microsoft Confirms Windows 11 25H2 UI Features Broken also Along With 24H2 Following Update
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

Entry 7
- [7] Examining the Risk of AI-Assisted MedusaLocker Ransomware Attacks
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
  - IOCs: --
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
  - IOCs: --
  - Source: https://gbhackers.com/phishing-attack-2/

Entry 10
- [10] Critical RSC Bugs in React and Next.js Allow Unauthenticated Remote Code Execution
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
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/critical-rsc-bugs-in-react-and-nextjs.html

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
    - filename: HRUpdate.exe, msiexec.exe
    - malware: APPDATA, SHA256
    - hash: 92a2e2a124a106af33993828fb0d4cdffd9dac8790169774d672c30747769455, 6246801035e053df2053b2dc28f4e76e3595fb62fdd02b5a50d9a2ed3796b153, 3ac90c071d143c3240974618d395fa3c5228904c8bf0a89a49f8c01cd7777421, 77a53dc757fdf381d3906ab256b74ad3cdb7628261c58a62bcc9c6ca605307ba
    - domain: even.net, cro.com
  - Source: https://gbhackers.com/matanbuchus-downloader/

Entry 12
- [12] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
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

Entry 13
- [13] WordPress King Addons Flaw Under Active Attack Lets Hackers Make Admin Accounts
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
    - ip: 182.8.226.228, 138.199.21.230, 206.238.221.25
    - filename: ajax.php
  - Source: https://thehackernews.com/2025/12/wordpress-king-addons-flaw-under-active.html

Entry 14
- [14] Picklescan Bugs Allow Malicious PyTorch Models to Evade Scans and Execute Code
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

Entry 15
- [15] Chopping AI Down to Size: Turning Disruptive Technology into a Strategic Advantage
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
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/chopping-ai-down-to-size-turning.html

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
- [17] [webapps] phpMyFAQ 2.9.8 - Cross-Site Request Forgery(CSRF)
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

Entry 18
- [18] [webapps] phpMyFAQ  2.9.8 - Cross-Site Request Forgery (CSRF)
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

Entry 19
- [19] [webapps] MaNGOSWebV4  4.0.6 - Reflected XSS
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

Entry 20
- [20] [webapps] MobileDetect 2.8.31 - Cross-Site Scripting (XSS)
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

Entry 21
- [21] [webapps] phpMyFaq 2.9.8 - Cross Site Request Forgery (CSRF)
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

Entry 22
- [22] [webapps] Django 5.1.13 - SQL Injection
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

Entry 23
- [23] [webapps] phpIPAM 1.4 - SQL-Injection
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

Entry 24
- [24] Malicious Rust Crate Delivers OS-Specific Malware to Web3 Developer Systems
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
    - domain: crates.io, download.videotalks, download.videotalks.xyz
  - Source: https://thehackernews.com/2025/12/malicious-rust-crate-delivers-os.html

Entry 25
- [25] [webapps] phpMyAdmin 5.0.0 - SQL Injection
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

Entry 26
- [26] [webapps] OpenRepeater 2.1 - OS Command Injection
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

Entry 27
- [27] [webapps] RosarioSIS 6.7.2 - Cross Site Scripting (XSS)
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

Entry 28
- [28] [webapps] PluckCMS 4.7.10 - Unrestricted File Upload
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

Entry 29
- [29] [webapps] openSIS Community Edition 8.0 - SQL Injection
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

Entry 30
- [30] [webapps] RosarioSIS 6.7.2 - Cross-Site Scripting (XSS)
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

Entry 31
- [31] ZDI-CAN-28260: Microsoft
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

Entry 32
- [32] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
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

Entry 33
- [33] ZDI-25-1040: (Pwn2Own) Synology DiskStation DS925+ samlAuth Authentication Bypass Vulnerability
  - Category: Other
  - Relevance: Medium (40)
  - Actionability: Critical (85)
  - Mitigations: --
  - Enablers: zero day
  - IOCs:
    - malware: ZDI-25-1040, AFFECTED, VENDORS, PRODUCTS, VULNERABILITY, DETAILS, SYNOPAMSSO, ADDITIONAL, DISCLOSURE, TIMELINE
  - Source: http://www.zerodayinitiative.com/advisories/ZDI-25-1040/

Entry 34
- [34] ZDI-25-1039: (Pwn2Own) Synology BeeStation Plus auth_info Stack-based Buffer Overflow Remote Code Execution Vulnerability
  - Category: Remote Code Execution
  - Relevance: Medium (40)
  - Actionability: High (70)
  - Mitigations: --
  - Enablers: zero day
  - IOCs:
    - malware: ZDI-25-1039, AFFECTED, VENDORS, PRODUCTS, VULNERABILITY, DETAILS, ADDITIONAL, DISCLOSURE, TIMELINE, CREDIT
  - Source: http://www.zerodayinitiative.com/advisories/ZDI-25-1039/