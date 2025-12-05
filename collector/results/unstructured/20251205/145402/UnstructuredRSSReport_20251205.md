## Summary

- Total findings: 48



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 12
**Data Completeness:** 75% (36/48 entries have threats+actors+MITRE)

Entry 1
- [1] Hackers Abuse Microsoft Teams Notifications to Launch Callback Phishing Attacks
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

Entry 2
- [2] Cloudflare Outage Triggers Widespread 500 Internal Server Errors
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

Entry 3
- [3] Russian Calisto Hackers Target NATO Research with ClickFix Malware
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

Entry 4
- [4] Hackers Exploiting ArrayOS AG VPN Vulnerability to Deploy Webshells
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

Entry 5
- [5] NCSC Launches Proactive Notification Service to Alert System Owners of Vulnerabilities
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

Entry 6
- [6] Russian Hackers Imitate European Events in Coordinated Phishing Campaigns
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

Entry 7
- [7] China-Nexus Hackers Target VMware vCenter Systems to Deploy Web Shells and Malware Implants
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

Entry 8
- [8] Hackers Using CastleRAT Malware to Attack Windows Systems and Gain Remote Access
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

Entry 9
- [9] EU fines X $140 million over deceptive blue checkmarks
  - Category: Other
  - Actionability: High (65)
  - MITRE Techniques:
    - T1656 — Impersonation
  - Mitigations:
    - T1656: User Training
  - Enablers: zero day
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/eu-fines-x-140-million-over-deceptive-blue-checkmarks-transparency-violations/

Entry 10
- [10] Pharma firm Inotiv discloses data breach after ransomware attack
  - Category: Data Theft
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1213.006 — Databases 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.006: User Training 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/pharma-firm-inotiv-discloses-data-breach-after-ransomware-attack/

Entry 11
- [11] Cacti Command Injection Flaw Allows Remote Execution of Malicious Code
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

Entry 12
- [12] Critical React2Shell flaw actively exploited in China-linked attacks
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

Entry 13
- [13] Cloudflare down, websites offline with 500 Internal Server Error
  - Category: Other
  - Actionability: Medium (30)
  - Mitigations: --
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/technology/cloudflare-down-websites-offline-with-500-internal-server-error/

Entry 14
- [14] Cloudflare blames today's outage on emergency React2Shell patch
  - Category: Remote Code Execution
  - Actionability: High (75)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1583.006 — Web Services 
    - T1587.004 — Exploits
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1583.006: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
    - domain: next.js
  - Source: https://www.bleepingcomputer.com/news/security/cloudflare-blames-todays-outage-on-emergency-react2shell-patch/

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
- [16] China-Nexus Hackers Exploiting React2Shell Vulnerability in Active Attacks
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

Entry 17
- [17] NCSC's ‘Proactive Notifications’ warns orgs of flaws in exposed devices
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

Entry 18
- [18] Predator spyware uses new infection vector for zero-click attacks
  - Category: Other
  - Actionability: High (75)
  - MITRE Techniques:
    - T1587.004 — Exploits
  - Mitigations:
    - T1587.004: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/predator-spyware-uses-new-infection-vector-for-zero-click-attacks/

Entry 19
- [19] Russia blocks FaceTime and Snapchat for alleged use by terrorists
  - Category: Other
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1566 — Phishing
  - Mitigations:
    - T1566: Audit
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/russia-blocks-facetime-and-snapchat-over-use-in-terrorist-attacks/

Entry 20
- [20] Critical React, Next.js flaw lets hackers execute code on servers
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

Entry 21
- [21] How strong password policies secure OT systems against cyber threats
  - Category: Other
  - Actionability: Informational (20)
  - MITRE Techniques:
    - T1592.002 — Software 
    - T1589.001 — Credentials
  - Mitigations:
    - T1592.002: Pre-compromise 
    - T1589.001: Pre-compromise
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/security/how-strong-password-policies-secure-ot-systems-against-cyber-threats/

Entry 22
- [22] Contractors with hacking records accused of wiping 96 govt databases
  - Category: Other
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1213.006 — Databases
  - Mitigations:
    - T1213.006: User Training
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/contractors-with-hacking-records-accused-of-wiping-96-govt-databases/

Entry 23
- [23] CISA warns of Chinese "BrickStorm" malware attacks on VMware servers
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

Entry 24
- [24] CISA Reports PRC Hackers Using BRICKSTORM for Long-Term Access in U.S. Systems
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

Entry 25
- [25] JPCERT Confirms Active Command Injection Attacks on Array AG Gateways
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

Entry 26
- [26] "Getting to Yes": An Anti-Sales Guide for MSPs
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

Entry 27
- [27] Intellexa Leaks Reveal Zero-Days and Ads-Based Vector for Predator Spyware Delivery
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
- [29] GoldFactory Hits Southeast Asia with Modified Banking Apps Driving 11,000+ Infections
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

Entry 30
- [30] ThreatsDay Bulletin: Wi-Fi Hack, npm Worm, DeFi Theft, Phishing Blasts— and 15 More Stories
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
- [32] Record 29.7 Tbps DDoS Attack Linked to AISURU Botnet with up to 4 Million Infected Hosts
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

Entry 33
- [33] Discover the AI Tools Fueling the Next Cybercrime Wave — Watch the Webinar
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

Entry 34
- [34] Lumia Security Raises $18 Million for AI Security and Governance
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/lumia, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/lumia-security-raises-18-million-for-ai-security-and-governance/

Entry 35
- [35] US Organizations Warned of Chinese Malware Used for Long-Term Persistence
  - Category: Other
  - Actionability: Informational (20)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/us, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/us-organizations-warned-of-chinese-malware-used-for-long-term-persistence/

Entry 36
- [36] WordPress King Addons Flaw Under Active Attack Lets Hackers Make Admin Accounts
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

Entry 37
- [37] Imper.ai Emerges From Stealth Mode With $28 Million in Funding
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1656 — Impersonation
  - Mitigations:
    - T1656: User Training
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/imper, https://www.securityweek.com
    - domain: securityweek.com, imper.ai
  - Source: https://www.securityweek.com/imper-ai-emerges-from-stealth-mode-with-28-million-in-funding/

Entry 38
- [38] Critical RSC Bugs in React and Next.js Allow Unauthenticated Remote Code Execution
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

Entry 39
- [39] Microsoft Silently Patches Windows LNK Flaw After Years of Active Exploitation
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

Entry 40
- [40] Aisuru Botnet Powers Record DDoS Attack Peaking at 29 Tbps
  - Category: DDoS/Botnet
  - Actionability: Informational (24)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/aisuru, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/aisuru-botnet-powers-record-ddos-attack-peaking-at-29-tbps/

Entry 41
- [41] Helmet Security Emerges From Stealth Mode With $9 Million in Funding
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/helmet, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/helmet-security-emerges-from-stealth-mode-with-9-million-in-funding/

Entry 42
- [42] India Rolls Back Order to Preinstall Cybersecurity App on Smartphones
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/india, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/india-rolls-back-order-to-preinstall-cybersecurity-app-on-smartphones/

Entry 43
- [43] Cybersecurity M&A Roundup: 30 Deals Announced in November 2025
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/cybersecurity, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/cybersecurity-ma-roundup-30-deals-announced-in-november-2025/

Entry 44
- [44] Chinese Hackers Exploiting React2Shell Vulnerability
  - Category: Other
  - Actionability: Medium (40)
  - Mitigations: --
  - Enablers: aws
  - IOCs:
    - url: https://www.securityweek.com/chinese, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/chinese-hackers-exploiting-react2shell-vulnerability/

Entry 45
- [45] Brazil Hit by Banking Trojan Spread via WhatsApp Worm and RelayNFC NFC Relay Fraud
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

Entry 46
- [46] Inotiv Says Personal Information Stolen in Ransomware Attack
  - Category: Ransomware
  - Actionability: Informational (25)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/inotiv, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/inotiv-says-personal-information-stolen-in-ransomware-attack/

Entry 47
- [47] Agentic Security Firm 7AI Raises $130 Million
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/agentic, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/agentic-security-firm-7ai-raises-130-million/

Entry 48
- [48] NCSC-2025-0380 [1.01] [H/H] Kwetsbaarheden verholpen in React Server Components
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0380