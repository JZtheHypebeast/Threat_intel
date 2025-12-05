## Summary

- Total findings: 38



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 3
**Data Completeness:** 92% (35/38 entries have threats+actors+MITRE)

Entry 1
- [1] Hackers Using CastleRAT Malware to Attack Windows Systems and Gain Remote Access
  - Category: Data Theft
  - Actionability: Informational (20)
  - MITRE Techniques:
    - T1113 — Screen Capture 
    - T1218.011 — Rundll32 
    - T1056.001 — Keylogging 
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1559 — Inter-Process Communication 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1059.006 — Python 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1218.011: Exploit Protection 
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1566: Audit 
    - T1559: Disable or Remove Feature or Program
  - IOCs:
    - filename: Eventvwr.exe, computerdefaults.exe, fodhelper.exe
    - malware: SHA256
    - hash: 963c012d56c62093d105ab5044517fdcce4ab826f7782b3e377932da1df6896d, f2ff4cbcd6d015af20e4e858b0f216c077ec6d146d3b2e0cbe68b56b3db7a0be, 4ef63fa536134ad296e83e37f9d323beb45087f7d306debdc3e096fed8357395, 282fa3476294e2b57aa9a8ab4bc1cc00f334197298e4afb2aae812b77e755207
  - Source: https://gbhackers.com/castlerat-malware/

Entry 2
- [2] China-Nexus Hackers Target VMware vCenter Systems to Deploy Web Shells and Malware Implants
  - Category: Data Theft
  - Actionability: Medium (32)
  - MITRE Techniques:
    - T1213.002 — Sharepoint 
    - T1213.006 — Databases 
    - T1588.006 — Vulnerabilities 
    - T1586.002 — Email Accounts 
    - T1036 — Masquerading 
    - T1064 — Scripting 
    - T1021.007 — Cloud Services 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.002: Audit 
    - T1213.006: User Training 
    - T1588.006: Pre-compromise 
    - T1586.002: Pre-compromise 
    - T1036: Audit
  - Enablers: phishing
  - IOCs:
    - malware: BRICKSTORM, DCERPC
  - Source: https://gbhackers.com/vmware-vcenter-systems/

Entry 3
- [3] Russian Hackers Imitate European Events in Coordinated Phishing Campaigns
  - Category: Data Theft
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1596.002 — WHOIS 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
    - T1036 — Masquerading 
    - T1090 — Proxy 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1596.002: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1583.001: Pre-compromise 
    - T1036: Audit 
    - T1090: Filter Network Traffic
  - Enablers: phishing
  - IOCs:
    - malware: UTA0355
    - domain: bsc2025.org, ustrs.com, forum.org, paris.com, 2025.com
  - Source: https://gbhackers.com/phishing-campaigns-2/

Entry 4
- [4] Russian Calisto Hackers Target NATO Research with ClickFix Malware
  - Category: Data Theft
  - Actionability: Medium (32)
  - MITRE Techniques:
    - T1557 — Adversary-in-the-Middle 
    - T1059.007 — JavaScript 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
    - T1090 — Proxy 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1557: Filter Network Traffic 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1588.006: Pre-compromise 
    - T1583.001: Pre-compromise 
    - T1090: Filter Network Traffic
  - Enablers: phishing
  - IOCs:
    - ip: 196.44.117.196
    - filename: a.pdf
  - Source: https://gbhackers.com/clickfix-malware/

Entry 5
- [5] Hackers Abuse Microsoft Teams Notifications to Launch Callback Phishing Attacks
  - Category: Other
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1566: Audit
  - Enablers: phishing
  - IOCs: --
  - Source: https://gbhackers.com/microsoft-teams-notifications-callback-phishing-attacks/

Entry 6
- [6] Cloudflare Outage Triggers Widespread 500 Internal Server Errors
  - Category: Phishing
  - Actionability: Medium (57)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1566: Audit
  - Enablers: phishing
  - IOCs: --
  - Source: https://gbhackers.com/cloudflare-outage-500-internal-server-errors/

Entry 7
- [7] NCSC Launches Proactive Notification Service to Alert System Owners of Vulnerabilities
  - Category: Phishing
  - Actionability: Medium (57)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1566: Audit 
    - T1592.002: Pre-compromise 
    - T1566.001: Antivirus/Antimalware
  - Enablers: phishing
  - IOCs:
    - domain: netcraft.com
  - Source: https://gbhackers.com/ncsc-launches-proactive-notification-service/

Entry 8
- [8] React2Shell critical flaw actively exploited in China-linked attacks
  - Category: Remote Code Execution
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1213.002 — Sharepoint 
    - T1059.007 — JavaScript 
    - T1588.006 — Vulnerabilities 
    - T1583.006 — Web Services 
    - T1592.002 — Software 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.002: Audit 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1588.006: Pre-compromise 
    - T1583.006: Pre-compromise 
    - T1592.002: Pre-compromise
  - Enablers: zero day
  - IOCs:
    - ip: 12.03.25.1
    - domain: next.js, pwned.txt
  - Source: https://www.bleepingcomputer.com/news/security/react2shell-critical-flaw-actively-exploited-in-china-linked-attacks/

Entry 9
- [9] Hackers Exploiting ArrayOS AG VPN Vulnerability to Deploy Webshells
  - Category: Other
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - malware: JPCERT
    - ip: 9.4.5.8, 194.233.100.138, 9.4.5.9
  - Source: https://gbhackers.com/arrayos-ag-vpn/

Entry 10
- [10] Cacti Command Injection Flaw Allows Remote Execution of Malicious Code
  - Category: Phishing
  - Actionability: Medium (57)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1566: Audit
  - Enablers: phishing
  - IOCs:
    - filename: host.php
  - Source: https://gbhackers.com/cacti-command-injection-flaw/

Entry 11
- [11] Cloudflare down, websites offline with 500 Internal Server Error
  - Category: Other
  - Actionability: Medium (30)
  - Mitigations: --
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/technology/cloudflare-down-websites-offline-with-500-internal-server-error/

Entry 12
- [12] NCSC's ‘Proactive Notifications’ warns orgs of flaws in exposed devices
  - Category: Ransomware
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
    - T1050 — New Service 
    - T1592.002 — Software 
    - T1566.001 — Spearphishing Attachment
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1583.001: Pre-compromise 
    - T1592.002: Pre-compromise 
    - T1566.001: Antivirus/Antimalware
  - IOCs:
    - ip: 12.03.25.1
    - domain: netcraft.com
  - Source: https://www.bleepingcomputer.com/news/security/ncscs-proactive-notifications-warns-orgs-of-flaws-in-exposed-devices/

Entry 13
- [13] China-Nexus Hackers Exploiting React2Shell Vulnerability in Active Attacks
  - Category: Phishing
  - Actionability: Medium (57)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1566: Audit 
    - T1587.004: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - Enablers: phishing
  - IOCs:
    - domain: next.js
  - Source: https://gbhackers.com/react2shell-vulnerability/

Entry 14
- [14] Russia blocks FaceTime and Snapchat for alleged use by terrorists
  - Category: Other
  - Actionability: Medium (40)
  - MITRE Techniques:
    - T1566 — Phishing
  - Mitigations:
    - T1566: Audit
  - Enablers: ai
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/russia-blocks-facetime-and-snapchat-over-use-in-terrorist-attacks/

Entry 15
- [15] Hackers are exploiting ArrayOS AG VPN flaw to plant webshells
  - Category: Remote Code Execution
  - Actionability: Critical (80)
  - Mitigations: --
  - Enablers: zero day
  - IOCs:
    - malware: JPCERT
    - ip: 9.4.5.8, 9.4.5.9, 12.03.25.1, 194.233.100.138
  - Source: https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-arrayos-ag-vpn-flaw-to-plant-webshells/

Entry 16
- [16] CISA warns of Chinese "BrickStorm" malware attacks on VMware servers
  - Category: Phishing
  - Actionability: Medium (32)
  - MITRE Techniques:
    - T1583.008 — Malvertising 
    - T1090 — Proxy 
    - T1589.001 — Credentials
  - Mitigations:
    - T1583.008: Pre-compromise 
    - T1090: Filter Network Traffic 
    - T1589.001: Pre-compromise
  - Enablers: phishing
  - IOCs:
    - malware: BRICKSTORM, UNC5221
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/cisa-warns-of-chinese-brickstorm-malware-attacks-on-vmware-servers/

Entry 17
- [17] Predator spyware uses new infection vector for zero-click attacks
  - Category: Other
  - Actionability: High (75)
  - MITRE Techniques:
    - T1587.004 — Exploits
  - Mitigations:
    - T1587.004: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/predator-spyware-uses-new-infection-vector-for-zero-click-attacks/

Entry 18
- [18] Contractors with hacking records accused of wiping 96 govt databases
  - Category: Other
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1213.006 — Databases
  - Mitigations:
    - T1213.006: User Training
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/contractors-with-hacking-records-accused-of-wiping-96-govt-databases/

Entry 19
- [19] Critical React, Next.js flaw lets hackers execute code on servers
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

Entry 20
- [20] How strong password policies secure OT systems against cyber threats
  - Category: Other
  - Actionability: Medium (40)
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
  - Enablers: ai
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/how-strong-password-policies-secure-ot-systems-against-cyber-threats/

Entry 21
- [21] Microsoft 365 license check bug blocks desktop app downloads
  - Category: Other
  - Actionability: Medium (30)
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

Entry 22
- [22] Critical flaw in WordPress add-on for Elementor exploited in attacks
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

Entry 23
- [23] Intellexa Leaks Reveal Zero-Days and Ads-Based Vector for Predator Spyware Delivery
  - Category: Data Theft
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1557 — Adversary-in-the-Middle 
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1204.001 — Malicious Link 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1557: Filter Network Traffic 
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise 
    - T1204.001: Network Intrusion Prevention
  - IOCs:
    - malware: PREYHUNTER
  - Source: https://thehackernews.com/2025/12/intellexa-leaks-reveal-zero-days-and.html

Entry 24
- [24] "Getting to Yes": An Anti-Sales Guide for MSPs
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - IOCs: --
  - Source: https://thehackernews.com/2025/12/getting-to-yes-anti-sales-guide-for-msps.html

Entry 25
- [25] Marquis data breach impacts over 74 US banks, credit unions
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

Entry 26
- [26] JPCERT Confirms Active Command Injection Attacks on Array AG Gateways
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1021.007 — Cloud Services 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1021.007: Multi-factor Authentication 
    - T1587.004: Pre-compromise 
    - T1593.001: Pre-compromise
  - IOCs:
    - malware: JPCERT
    - ip: 9.4.5.8, 9.4.5.9, 194.233.100.138
  - Source: https://thehackernews.com/2025/12/jpcert-confirms-active-command.html

Entry 27
- [27] CISA Reports PRC Hackers Using BRICKSTORM for Long-Term Access in U.S. Systems
  - Category: Data Theft
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1213.002 — Sharepoint 
    - T1584.008 — Network Devices 
    - T1588.006 — Vulnerabilities 
    - T1586.002 — Email Accounts 
    - T1036 — Masquerading 
    - T1076 — Remote Desktop Protocol 
    - T1505.003 — Web Shell 
    - T1090 — Proxy 
    - T1021.007 — Cloud Services 
    - T1556.006 — Multi-Factor Authentication 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.002: Audit 
    - T1584.008: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1586.002: Pre-compromise 
    - T1036: Audit
  - IOCs:
    - malware: BRICKSTORM, UNC5221
  - Source: https://thehackernews.com/2025/12/cisa-reports-prc-hackers-using.html

Entry 28
- [28] Silver Fox Uses Fake Microsoft Teams Installer to Spread ValleyRAT Malware in China
  - Category: Data Theft
  - Actionability: Medium (32)
  - MITRE Techniques:
    - T1053.005 — Scheduled Task 
    - T1218.011 — Rundll32 
    - T1021.007 — Cloud Services 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1608.006 — SEO Poisoning 
    - T1574.002 — DLL Side-Loading 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1053.005: Privileged Account Management 
    - T1218.011: Exploit Protection 
    - T1021.007: Multi-factor Authentication 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: phishing
  - IOCs:
    - filename: amsSetup.zip, Setup.exe, 360tray.exe, Verifier.exe, AutoRecoverDat.dll, rundll32.exe, men.exe, NVIDIA.exe, bypass.exe
    - malware: NVIDIA
  - Source: https://thehackernews.com/2025/12/silver-fox-uses-fake-microsoft-teams.html

Entry 29
- [29] ThreatsDay Bulletin: Wi-Fi Hack, npm Worm, DeFi Theft, Phishing Blasts— and 15 More Stories
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

Entry 30
- [30] GoldFactory Hits Southeast Asia with Modified Banking Apps Driving 11,000+ Infections
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

Entry 31
- [31] 5 Threats That Reshaped Web Security This Year [2025]
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

Entry 32
- [32] Critical RSC Bugs in React and Next.js Allow Unauthenticated Remote Code Execution
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

Entry 33
- [33] Record 29.7 Tbps DDoS Attack Linked to AISURU Botnet with up to 4 Million Infected Hosts
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

Entry 34
- [34] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
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

Entry 35
- [35] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
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

Entry 36
- [36] Brazil Hit by Banking Trojan Spread via WhatsApp Worm and RelayNFC NFC Relay Fraud
  - Category: Data Theft
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
  - IOCs:
    - filename: svchost.exe
    - domain: executed.dat, test.ikotech, manoelimoveiscaioba.com, serverseistemasatu.com, maisseguraca.site, test.ikotech.online
  - Source: https://thehackernews.com/2025/12/brazil-hit-by-banking-trojan-spread-via.html

Entry 37
- [37] WordPress King Addons Flaw Under Active Attack Lets Hackers Make Admin Accounts
  - Category: Other
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
  - IOCs:
    - ip: 2602:fa59:3:424::1, 45.61.157.120, 182.8.226.228, 138.199.21.230, 206.238.221.25
    - filename: ajax.php
  - Source: https://thehackernews.com/2025/12/wordpress-king-addons-flaw-under-active.html

Entry 38
- [38] NCSC-2025-0380 [1.01] [H/H] Kwetsbaarheden verholpen in React Server Components
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0380