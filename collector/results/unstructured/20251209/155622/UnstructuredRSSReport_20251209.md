## Summary

- Total findings: 33



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 8
**Data Completeness:** 75% (25/33 entries have threats+actors+MITRE)

Entry 1
- [1] Hackers Exploit Ivanti Connect Secure Vulnerabilities to Spread MetaRAT Malware
  - Category: Data Theft
  - Actionability: Medium (57)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1056.001 — Keylogging 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1073 — DLL Side-Loading 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1027.015 — Compression 
    - T1574.002 — DLL Side-Loading 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise 
    - T1027.015: Antivirus/Antimalware
  - Enablers: phishing
  - IOCs:
    - malware: ERR31093
    - filename: mytilus3.dll
    - domain: vnifile.hlp, deploy.net
  - Source: https://gbhackers.com/metarat-malware/

Entry 2
- [2] SAP Security Patch Day Fixes Critical Flaws in Solution Manager, NetWeaver & More
  - Category: Remote Code Execution
  - Actionability: High (60)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits
  - Mitigations:
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: cloud
  - IOCs:
    - malware: HY_COM, COM_CLOUD, ENTERPRISE, RUNTIME, SAPUI5
    - domain: deploy.net
  - Source: https://gbhackers.com/sap-security-patch-day-fixes-critical-flaws/

Entry 3
- [3] New Vishing Attack Exploits Microsoft Teams and QuickAssist to Deploy .NET Malware
  - Category: Other
  - Actionability: Medium (45)
  - MITRE Techniques:
    - T1566 — Phishing 
    - T1219 — Remote Access Software 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1656 — Impersonation 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1566: Audit 
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1656: User Training
  - IOCs:
    - filename: updater.exe, verify.php, loader.dll
    - domain: deploy.net, stage.net, a.net, exploits.net, the.net, monitoring.net, ciscocyber.com
  - Source: https://gbhackers.com/new-vishing-attack/

Entry 4
- [4] Malicious MCP Servers Enable Stealthy Prompt Injection to Drain System Resources
  - Category: Data Theft
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - domain: deploy.net
  - Source: https://gbhackers.com/malicious-mcp-servers-enable-stealthy-prompt-injection/

Entry 5
- [5] Malicious VS Code on Microsoft Registry Steals WiFi Passwords and Captures Screens
  - Category: Phishing
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1059.001 — PowerShell 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1059.001: Disable or Remove Feature or Program 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise
  - Enablers: phishing
  - IOCs:
    - malware: COOL_SCREENSHOT_MUTEX_YARRR
    - domain: extension.js, bat.sh, deploy.net
    - filename: lightshot.exe
  - Source: https://gbhackers.com/malicious-vs-code/

Entry 6
- [6] AI-Driven Tools Uncover GhostPenguin Backdoor Attacking Linux Servers
  - Category: Ransomware
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1219: Execution Prevention 
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1583.001: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: ai
  - IOCs:
    - domain: deploy.net
  - Source: https://gbhackers.com/ai-driven-tools/

Entry 7
- [7] Burp Suite Upgrades Scanner With Detection for Critical React2Shell Flaws
  - Category: Ransomware
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits
  - Mitigations:
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: ai
  - IOCs:
    - domain: deploy.net
  - Source: https://gbhackers.com/burp-suite-upgrades-scanner-for-critical-react2shell-flaws/

Entry 8
- [8] Akira Group Targets Hyper-V and VMware ESXi with Ransomware Exploiting Vulnerabilities
  - Category: Other
  - Actionability: Medium (50)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1087.002 — Domain Account 
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1556.006 — Multi-Factor Authentication 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1078.003 — Local Accounts
  - Mitigations:
    - T1219: Execution Prevention 
    - T1087.002: Operating System Configuration 
    - T1588.006: Pre-compromise 
    - T1556.006: User Account Management 
    - T1587.004: Pre-compromise
  - IOCs:
    - domain: vmkernel.boot.execinstalledonly, deploy.net
  - Source: https://gbhackers.com/akira-group/

Entry 9
- [9] North Korean hackers exploit React2Shell flaw in EtherRAT malware attacks
  - Category: Other
  - Actionability: High (65)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1059.007 — JavaScript 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1589.001: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - ip: 12.03.25.1
    - domain: next.js, node.js, s.sh, nodejs.org, kxnzl4mtez.js
  - Source: https://www.bleepingcomputer.com/news/security/north-korean-hackers-exploit-react2shell-flaw-in-etherrat-malware-attacks/

Entry 10
- [10] Microsoft investigates Copilot outage affecting users in Europe
  - Category: Other
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1590.005 — IP Addresses
  - Mitigations:
    - T1590.005: Pre-compromise
  - IOCs:
    - malware: CP1193544, DZ1193516
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-investigates-copilot-outage-affecting-users-in-europe/

Entry 11
- [11] Ransomware IAB abuses EDR for stealthy malware execution
  - Category: Other
  - Actionability: Medium (45)
  - MITRE Techniques:
    - T1574.002 — DLL Side-Loading 
    - T1204.002 — User Execution: Malicious File 
    - T1590.005 — IP Addresses 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1486 — Data Encrypted for Impact 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1204.002: Execution Prevention 
    - T1590.005: Pre-compromise 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit 
    - T1592.002: Pre-compromise
  - IOCs:
    - filename: SentinelAgentCore.dll, sentinelagentworker.exe, reg.exe, findstr.exe
    - malware: SYSTEM
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/ransomware-iab-abuses-edr-for-stealthy-malware-execution/

Entry 12
- [12] New Variant of Mirai Botnet ‘Broadside’ Launches Active Attacks on Users
  - Category: Other
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1590.005 — IP Addresses 
    - T1087.001 — Local Account 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1110 — Brute Force 
    - T1587.004 — Exploits 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1219: Execution Prevention 
    - T1590.005: Pre-compromise 
    - T1087.001: Operating System Configuration 
    - T1588.006: Pre-compromise 
    - T1110: User Account Management
  - IOCs:
    - domain: device.rsp, deploy.net
  - Source: https://gbhackers.com/mirai-botnet-2/

Entry 13
- [13] FinCEN says ransomware gangs extorted over $2.1B from 2022 to 2024
  - Category: Ransomware
  - Actionability: High (68)
  - MITRE Techniques:
    - T1590.005 — IP Addresses
  - Mitigations:
    - T1590.005: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
    - domain: bleepingcomputer.com
  - Source: https://www.bleepingcomputer.com/news/security/fincen-says-ransomware-gangs-extorted-over-21b-from-2022-to-2024/

Entry 14
- [14] Malicious VSCode extensions on Microsoft's registry drop infostealers
  - Category: Phishing
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1059.001 — PowerShell 
    - T1589.001 — Credentials
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1059.001: Disable or Remove Feature or Program 
    - T1589.001: Pre-compromise
  - Enablers: phishing
  - IOCs:
    - malware: APPDATA
    - ip: 12.03.25.1
    - domain: bleepingcomputer.com, bat.sh
    - filename: runtime.exe
  - Source: https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-on-microsofts-registry-drop-infostealers/

Entry 15
- [15] Ransomware gangs turn to Shanya EXE packer to hide EDR killers
  - Category: Other
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1073 — DLL Side-Loading 
    - T1027.015 — Compression 
    - T1486 — Data Encrypted for Impact 
    - T1574.002 — DLL Side-Loading
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1027.015: Antivirus/Antimalware 
    - T1486: Behavior Prevention on Endpoint
  - IOCs:
    - filename: shell32.dll, consent.exe, version.dll, rtworkq.dll, msimg32.dll, wmsgapi.dll
    - ip: 12.03.25.1
    - domain: and.text, throttlestop.sys, rwdrv.sys
  - Source: https://www.bleepingcomputer.com/news/security/ransomware-gangs-turn-to-shanya-exe-packer-to-hide-edr-killers/

Entry 16
- [16] Poland arrests Ukrainians utilizing 'advanced' hacking equipment
  - Category: Ransomware
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1213.006 — Databases 
    - T1592.002 — Software
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1213.006: User Training 
    - T1592.002: Pre-compromise
  - IOCs:
    - malware: FLIPPER
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/poland-arrests-ukrainians-utilizing-advanced-hacking-equipment/

Entry 17
- [17] Storm-0249 Escalates Ransomware Attacks with ClickFix, Fileless PowerShell, and DLL Sideloading
  - Category: Data Theft
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1574.002 — DLL Side-Loading 
    - T1204.002 — User Execution: Malicious File 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1593.001 — Social Media 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1204.002: Execution Prevention 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit
  - IOCs:
    - filename: curl.exe, SentinelAgentCore.dll, SentinelAgentWorker.exe, reg.exe, findstr.exe
    - malware: SYSTEM, BRICKSTORM, AISURU
    - domain: us.microsoft.com, next.js
  - Source: https://thehackernews.com/2025/12/storm-0249-escalates-ransomware-attacks.html

Entry 18
- [18] Hackers Using FLIPPER Devices to Breach IT Systems Arrested by Authorities
  - Category: Ransomware
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1219 — Remote Access Software 
    - T1588.006 — Vulnerabilities 
    - T1064 — Scripting 
    - T1587.004 — Exploits
  - Mitigations:
    - T1219: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise
  - Enablers: ai
  - IOCs:
    - malware: FLIPPER
    - domain: deploy.net
  - Source: https://gbhackers.com/hackers-using-flipper-devices-to-breach-arrested-by-authorities/

Entry 19
- [19] Google Chrome adds new security layer for Gemini AI agentic browsing
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1566 — Phishing 
    - T1589.001 — Credentials
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1566: Audit 
    - T1589.001: Pre-compromise
  - Enablers: ai
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/google-chrome-adds-new-security-layer-for-gemini-ai-agentic-browsing/

Entry 20
- [20] How to Streamline Zero Trust Using the Shared Signals Framework
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1145 — Private Keys 
    - T1566 — Phishing 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1593.001: Pre-compromise 
    - T1589.001: Pre-compromise
  - IOCs:
    - malware: JWT_SIGN, BRICKSTORM, AISURU
    - domain: example.okta.com, example.oktapreview.com, a.well, the.well, next.js
  - Source: https://thehackernews.com/2025/12/how-to-streamline-zero-trust-using.html

Entry 21
- [21] React2Shell Attacks Linked to North Korean Hackers
  - Category: Other
  - Actionability: Medium (40)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/react2shell, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/react2shell-attacks-linked-to-north-korean-hackers/

Entry 22
- [22] Researchers Find Malicious VS Code, Go, npm, and Rust Packages Stealing Developer Data
  - Category: Data Theft
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1593.001 — Social Media 
    - T1027.015 — Compression 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1059.001: Disable or Remove Feature or Program 
    - T1566: Audit 
    - T1592.002: Pre-compromise
  - Enablers: phishing
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - domain: belowbigblack.bitcoin, bigblack.codo, bigblack.mrbigblacktheme, bigblack.bitcoin, system.io.compression, next.js, syn1112223334445556667778889990.org, github.com
  - Source: https://thehackernews.com/2025/12/researchers-find-malicious-vs-code-go.html

Entry 23
- [23] Identity Security Firm Saviynt Raises $700 Million at $3 Billion Valuation
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/identity, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/identity-security-firm-saviynt-raises-700-million-at-3-billion-valuation/

Entry 24
- [24] US Posts $10 Million Bounty for Iranian Hackers
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/us, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/us-posts-10-million-bounty-for-iranian-hackers/

Entry 25
- [25] Proofpoint Completes $1.8 Billion Acquisition of Hornetsecurity
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/proofpoint, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/proofpoint-completes-1-8-billion-acquisition-of-hornetsecurity/

Entry 26
- [26] Google Adds Layered Defenses to Chrome to Block Indirect Prompt Injection Threats
  - Category: Data Theft
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1566 — Phishing 
    - T1593.001 — Social Media 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1593.001: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/google-adds-layered-defenses-to-chrome.html

Entry 27
- [27] Over 300,000 Individuals Impacted by Vitas Hospice Data Breach
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/over, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/over-300000-individuals-impacted-by-vitas-hospice-data-breach/

Entry 28
- [28] Equixly Raises $11 Million for AI-Powered API Penetration Testing
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/equixly, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/equixly-raises-11-million-for-ai-powered-api-penetration-testing/

Entry 29
- [29] New ‘Broadside’ Botnet Poses Risk to Shipping Companies
  - Category: DDoS/Botnet
  - Actionability: Informational (24)
  - MITRE Techniques:
    - T1589.001 — Credentials
  - Mitigations:
    - T1589.001: Pre-compromise
  - IOCs:
    - url: https://www.securityweek.com/new, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/new-broadside-botnet-poses-risk-to-shipping-companies/

Entry 30
- [30] Experts Confirm JS#SMUGGLER Uses Compromised Sites to Deploy NetSupport RAT
  - Category: Phishing
  - Actionability: Informational (22)
  - MITRE Techniques:
    - T1204.002 — User Execution: Malicious File 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1090 — Proxy 
    - T1218.005 — Mshta 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials
  - Mitigations:
    - T1204.002: Execution Prevention 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1090: Filter Network Traffic 
    - T1218.005: Execution Prevention
  - Enablers: phishing
  - IOCs:
    - filename: mshta.exe, QNaZg.exe
    - malware: SMUGGLER, CHAMELEON, BRICKSTORM, AISURU
    - domain: phone.js, vb.net, filessvchost.js, a.net
  - Source: https://thehackernews.com/2025/12/experts-confirm-jssmuggler-uses.html

Entry 31
- [31] STAC6565 Targets Canada in 80% of Attacks as Gold Blade Deploys QWCrypt Ransomware
  - Category: Data Theft
  - Actionability: Medium (37)
  - MITRE Techniques:
    - T1218.011 — Rundll32 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1583.001 — Domains 
    - T1062 — Hypervisor 
    - T1090 — Proxy 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1556.006 — Multi-Factor Authentication 
    - T1593.001 — Social Media 
    - T1566.001 — Spearphishing Attachment 
    - T1574.002 — DLL Side-Loading 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1218.011: Exploit Protection 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1583.001: Pre-compromise 
    - T1090: Filter Network Traffic
  - Enablers: phishing
  - IOCs:
    - filename: rundll32.exe, ADNotificationManager.exe, srvcli.dll, netutils.dll, pcalua.exe
    - malware: STAC6565, SOCKS5, BRICKSTORM, AISURU
    - domain: malicious.dat
  - Source: https://thehackernews.com/2025/12/stac6565-targets-canada-in-80-of.html

Entry 32
- [32] Google Fortifies Chrome Agentic AI Against Indirect Prompt Injection Attacks
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/google, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/google-fortifies-chrome-agentic-ai-against-indirect-prompt-injection-attacks/

Entry 33
- [33] NCSC-2025-0382 [1.00] [M/H] Kwetsbaarheden verholpen in Siemens producten
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0382