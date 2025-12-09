## Summary

- Total findings: 46



---

# Threat Intelligence Summary


## Detailed Entries

**Validation Summary:** missing threats: 0, missing actors: 0, missing MITRE: 11
**Data Completeness:** 76% (35/46 entries have threats+actors+MITRE)

Entry 1
- [1] LOLPROX Unveils Undetected Exploitation Routes for Stealthy Hypervisor Attacks
  - Category: Data Theft
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - malware: LOLPROX, SYSTEM
    - domain: ntds.dit, next.js, cal.com
  - Source: https://gbhackers.com/hypervisor-attacks/

Entry 2
- [2] WatchGuard Firebox Vulnerabilities Let Hackers Skip Integrity Validation and Plant Malicious Code
  - Category: Other
  - Actionability: Critical (90)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting
  - Mitigations:
    - T1588.006: Pre-compromise
  - IOCs:
    - malware: LOLPROX
    - domain: next.js, cal.com
  - Source: https://gbhackers.com/watchguard-firebox-vulnerabilities/

Entry 3
- [3] OceanLotus Targets Xinchuang Ecosystem with Sophisticated Supply Chain Attacks
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1053.005 — Scheduled Task 
    - T1204.002 — Malicious File 
    - T1588.006 — Vulnerabilities 
    - T1195 — Supply Chain Compromise 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1566 — Phishing 
    - T1110 — Brute Force 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1059.006 — Python 
    - T1566.001 — Spearphishing Attachment 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1053.005: Privileged Account Management 
    - T1204.002: Execution Prevention 
    - T1588.006: Pre-compromise 
    - T1195: Boot Integrity 
    - T1566: Audit
  - IOCs:
    - malware: SNAPSHOT, LOLPROX
    - domain: snapshot.jar, version.epub, 7803.desktop, the.config, next.js, cal.com
  - Source: https://gbhackers.com/xinchuang-ecosystem/

Entry 4
- [4] CISA Adds Critical React2Shell Vulnerability to KEV Catalog After Active Exploitation
  - Category: Other
  - Actionability: Critical (90)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting
  - Mitigations:
    - T1588.006: Pre-compromise
  - Enablers: ai
  - IOCs:
    - malware: LOLPROX
    - domain: next.js, cal.com
  - Source: https://gbhackers.com/cisa-adds-critical-react2shell-vulnerability-to-kev-catalog/

Entry 5
- [5] Indonesia’s Gambling Industry Reveals Clues of Nationwide Cyber Involvement
  - Category: Data Theft
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1583.001 — Domains 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1583.001: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - malware: LOLPROX
    - domain: deltaslot88.apk, jayaplay168.apk, next.js, cal.com, namesvr.dev
  - Source: https://gbhackers.com/indonesias-gambling/

Entry 6
- [6] Next.js Releases Scanner to Detect and Fix Apps Affected by React2Shell Vulnerability
  - Category: Remote Code Execution
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting
  - Mitigations:
    - T1588.006: Pre-compromise
  - IOCs:
    - malware: LOLPROX
    - domain: next.js, cal.com
    - filename: package.json
  - Source: https://gbhackers.com/next-js-releases-scanner-react2shell-vulnerability/

Entry 7
- [7] Porsche Cars Disabled After Major Failure in Installed Satellite Security System
  - Category: Other
  - Actionability: Critical (90)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1592.002 — Software
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1592.002: Pre-compromise
  - Enablers: ai
  - IOCs:
    - malware: LOLPROX
    - domain: next.js, cal.com
  - Source: https://gbhackers.com/porsche-cars-disabled-after-failure-in-installed-satellite-security-system/

Entry 8
- [8] Hackers Target Developers Using Malicious VS Code and Cursor AI Extensions
  - Category: Data Theft
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1589.001 — Credentials 
    - T1059.006 — Python 
    - T1041 — Exfiltration Over C2 Channel 
    - T1190 — Exploit Public-Facing Application 
    - T1059 — Command and Scripting Interpreter 
    - T1547 — Boot or Logon Autostart Execution
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1592.002: Pre-compromise 
    - T1587.004: Pre-compromise 
    - T1589.001: Pre-compromise 
    - T1059.006: Audit
  - Enablers: ai
  - IOCs:
    - malware: LOLPROX
    - domain: next.js, cal.com
  - Source: https://gbhackers.com/vs-code-and-cursor-ai/

Entry 9
- [9] OpenAI denies rolling out ads on ChatGPT paid plans
  - Category: Other
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1590.005 — IP Addresses
  - Mitigations:
    - T1590.005: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/artificial-intelligence/openai-denies-rolling-out-ads-on-chatgpt-paid-plans/

Entry 10
- [10] Portugal updates cybercrime law to exempt security researchers
  - Category: Other
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1557.004 — Evil Twin 
    - T1566 — Phishing
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1557.004: Network Intrusion Prevention 
    - T1566: Audit
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/portugal-updates-cybercrime-law-to-exempt-security-researchers/

Entry 11
- [11] Critical Cal.com Flaw Allows Attackers to Bypass Authentication Using Fake TOTP Codes
  - Category: Other
  - Actionability: Informational (20)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1556.006 — Multi-Factor Authentication 
    - T1589.001 — Credentials 
    - T1656 — Impersonation
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1556.006: User Account Management 
    - T1589.001: Pre-compromise 
    - T1656: User Training
  - IOCs:
    - malware: LOLPROX
    - domain: cal.com, options.ts, next.js
  - Source: https://gbhackers.com/critical-cal-com-flaw-allows-attackers-to-bypass-authentication-using-fake-totp-codes/

Entry 12
- [12] React2Shell flaw exploited to breach 30 orgs, 77k IP addresses vulnerable
  - Category: Remote Code Execution
  - Actionability: High (60)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1059.001 — PowerShell
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1059.001: Disable or Remove Feature or Program
  - Enablers: aws
  - IOCs:
    - malware: UNC5174
    - ip: 12.03.25.1, 23.235.188.3
    - domain: next.js, bleepingcomputer.com
  - Source: https://www.bleepingcomputer.com/news/security/react2shell-flaw-exploited-to-breach-30-orgs-77k-ip-addresses-vulnerable/

Entry 13
- [13] New wave of VPN login attempts targets Palo Alto GlobalProtect portals
  - Category: DDoS/Botnet
  - Actionability: Medium (52)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities 
    - T1556.006 — Multi-Factor Authentication 
    - T1592.002 — Software
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise 
    - T1556.006: User Account Management 
    - T1592.002: Pre-compromise
  - IOCs:
    - malware: AS200373
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/new-wave-of-vpn-login-attempts-targets-palo-alto-globalprotect-portals/

Entry 14
- [14] Barts Health NHS discloses data breach after Oracle zero-day hack
  - Category: Ransomware
  - Actionability: Critical (100)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1213.006 — Databases 
    - T1592.002 — Software
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1213.006: User Training 
    - T1592.002: Pre-compromise
  - Enablers: zero-day, zero day
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/barts-health-nhs-discloses-data-breach-after-oracle-zero-day-hack/

Entry 15
- [15] FBI warns of virtual kidnapping scams using altered social media photos
  - Category: Ransomware
  - Actionability: Critical (80)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1593.001 — Social Media
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1593.001: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/fbi-warns-of-virtual-kidnapping-ransom-scams-using-altered-social-media-photos/

Entry 16
- [16] Shanya EDR Killer: The New Favorite Tool for Ransomware Operators
  - Category: Other
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1588.006 — Vulnerabilities 
    - T1062 — Hypervisor 
    - T1064 — Scripting 
    - T1073 — DLL Side-Loading 
    - T1587.004 — Exploits 
    - T1574.002 — DLL Side-Loading
  - Mitigations:
    - T1588.006: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - malware: LOLPROX
    - domain: for.net, throttlestop.sys, booking.com, next.js
    - filename: consent.exe, msimg32.dll, shell32.dll
  - Source: https://gbhackers.com/shanya-edr-killer/

Entry 17
- [17] A Practical Guide to Continuous Attack Surface Visibility
  - Category: Other
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1588.006 — Vulnerabilities
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1588.006: Pre-compromise
  - IOCs:
    - malware: AUTHOR
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/a-practical-guide-to-continuous-attack-surface-visibility/

Entry 18
- [18] Cloudflare down, websites offline with 500 Internal Server Error
  - Category: Other
  - Actionability: Informational (10)
  - Mitigations: --
  - IOCs: --
  - Source: https://www.bleepingcomputer.com/news/technology/cloudflare-down-websites-offline-with-500-internal-server-error/

Entry 19
- [19] Cloudflare blames today's outage on React2Shell mitigations
  - Category: Remote Code Execution
  - Actionability: Critical (85)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1059.007 — JavaScript 
    - T1583.006 — Web Services 
    - T1587.004 — Exploits
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1583.006: Pre-compromise 
    - T1587.004: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
    - domain: next.js
  - Source: https://www.bleepingcomputer.com/news/security/cloudflare-blames-todays-outage-on-emergency-react2shell-patch/

Entry 20
- [20] EU fines X $140 million over deceptive blue checkmarks
  - Category: Other
  - Actionability: High (65)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1656 — Impersonation
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1656: User Training
  - Enablers: zero day
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/eu-fines-x-140-million-over-deceptive-blue-checkmarks-transparency-violations/

Entry 21
- [21] Critical React2Shell flaw actively exploited in China-linked attacks
  - Category: Remote Code Execution
  - Actionability: Critical (85)
  - MITRE Techniques:
    - T1213.002 — Sharepoint 
    - T1590.005 — IP Addresses 
    - T1059.007 — JavaScript 
    - T1588.006 — Vulnerabilities 
    - T1583.006 — Web Services 
    - T1587.004 — Exploits
  - Mitigations:
    - T1213.002: Audit 
    - T1590.005: Pre-compromise 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1588.006: Pre-compromise 
    - T1583.006: Pre-compromise
  - IOCs:
    - ip: 12.03.25.1
    - domain: next.js, pwned.txt
  - Source: https://www.bleepingcomputer.com/news/security/react2shell-critical-flaw-actively-exploited-in-china-linked-attacks/

Entry 22
- [22] Pharma firm Inotiv discloses data breach after ransomware attack
  - Category: Data Theft
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1213.006 — Databases 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1213.006: User Training 
    - T1041: Network Intrusion Prevention
  - IOCs:
    - ip: 12.03.25.1
  - Source: https://www.bleepingcomputer.com/news/security/pharma-firm-inotiv-discloses-data-breach-after-ransomware-attack/

Entry 23
- [23] Sneeit WordPress RCE Exploited in the Wild While ICTBroadcast Bug Fuels Frost Botnet Attacks
  - Category: Phishing
  - Actionability: High (74)
  - MITRE Techniques:
    - T1190 — Exploit Public-Facing Application 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1190: Application Isolation and Sandboxing 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise 
    - T1566: Audit
  - Enablers: phishing
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - ip: 185.125.50.59, 182.8.226.51, 89.187.175.80, 194.104.147.192, 196.251.100.39, 114.10.116.226, 116.234.108.143, 87.121.84.52
  - Source: https://thehackernews.com/2025/12/sneeit-wordpress-rce-exploited-in-wild.html

Entry 24
- [24] Zero-Click Agentic Browser Attack Can Delete Entire Google Drive Using Crafted Emails
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise 
    - T1566: Audit 
    - T1587.004: Pre-compromise
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - domain: example, next.js, example.com
  - Source: https://thehackernews.com/2025/12/zero-click-agentic-browser-attack-can.html

Entry 25
- [25] MuddyWater Deploys UDPGangster Backdoor in Targeted Turkey-Israel-Azerbaijan Campaign
  - Category: Data Theft
  - Actionability: Informational (12)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1566 — Phishing 
    - T1593.001 — Social Media 
    - T1566.001 — Spearphishing Attachment 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1593.001: Pre-compromise 
    - T1566.001: Antivirus/Antimalware
  - Enablers: phishing
  - IOCs:
    - filename: seminer.zip, VBoxTray.exe, vmware.exe, cmd.exe
    - malware: VIRTUAL, VIRTUALBOX, VMWARE, BRICKSTORM, AISURU
    - ip: 157.20.182.75
  - Source: https://thehackernews.com/2025/12/muddywater-deploys-udpgangster-backdoor.html

Entry 26
- [26] Critical React2Shell Flaw Added to CISA KEV After Confirmed Active Exploitation
  - Category: Other
  - Actionability: High (75)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1583.006 — Web Services 
    - T1059.001 — PowerShell 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise 
    - T1583.006: Pre-compromise
  - IOCs:
    - malware: UNC5174, SNOWLIGHT, BRICKSTORM, AISURU
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/critical-react2shell-flaw-added-to-cisa.html

Entry 27
- [27] Android Malware FvncBot, SeedSnatcher, and ClayRat Gain Stronger Data Theft Features
  - Category: Data Theft
  - Actionability: Informational (20)
  - MITRE Techniques:
    - T1056.001 — Keylogging 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1659 — Content Injection 
    - T1218.002 — Control Panel 
    - T1566 — Phishing 
    - T1593.001 — Social Media 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1659: Restrict Web-Based Content 
    - T1218.002: Restrict File and Directory Permissions 
    - T1566: Audit
  - IOCs:
    - malware: CYFIRMA, FLAG_SECURE, BRICKSTORM, AISURU
    - domain: naleymilva.it.com, next.js
  - Source: https://thehackernews.com/2025/12/android-malware-fvncbot-seedsnatcher.html

Entry 28
- [28] Critical XXE Bug CVE-2025-66516 (CVSS 10.0) Hits Apache Tika, Requires Urgent Patch
  - Category: Other
  - Actionability: Medium (35)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1566 — Phishing 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1593.001: Pre-compromise
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - domain: packagesorg.apache.tika, org.apache.tika, next.js
  - Source: https://thehackernews.com/2025/12/critical-xxe-bug-cve-2025-66516-cvss.html

Entry 29
- [29] Chinese Hackers Have Started Exploiting the Newly Disclosed React2Shell Vulnerability
  - Category: Other
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1590.005 — IP Addresses 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1195 — Supply Chain Compromise 
    - T1583.006 — Web Services 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media
  - Mitigations:
    - T1590.005: Pre-compromise 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise 
    - T1195: Boot Integrity
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - domain: pwned.txt, next.js
  - Source: https://thehackernews.com/2025/12/chinese-hackers-have-started-exploiting.html

Entry 30
- [30] Researchers Uncover 30+ Flaws in AI Coding Tools Enabling Data Theft and RCE Attacks
  - Category: Data Theft
  - Actionability: Informational (25)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1195 — Supply Chain Compromise 
    - T1566 — Phishing 
    - T1592.002 — Software 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise 
    - T1195: Boot Integrity 
    - T1566: Audit
  - Enablers: ai
  - IOCs:
    - filename: php.validate.exe, settings.json
    - malware: PATH_TO_GIT, README, BRICKSTORM, AISURU
    - domain: kiro.dev, zed.dev, workspace.xml, php.validate.executablepath
  - Source: https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html

Entry 31
- [31] Intellexa Leaks Reveal Zero-Days and Ads-Based Vector for Predator Spyware Delivery
  - Category: Data Theft
  - Actionability: Medium (30)
  - MITRE Techniques:
    - T1557 — Adversary-in-the-Middle 
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1566 — Phishing 
    - T1587.004 — Exploits 
    - T1593.001 — Social Media 
    - T1204.001 — Malicious Link 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1557: Filter Network Traffic 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1587.004: Pre-compromise
  - IOCs:
    - malware: PREYHUNTER, BRICKSTORM, AISURU
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/intellexa-leaks-reveal-zero-days-and.html

Entry 32
- [32] Ransomware Payments Surpassed $4.5 Billion: US Treasury
  - Category: Ransomware
  - Actionability: High (65)
  - MITRE Techniques:
    - T1486 — Data Encrypted for Impact
  - Mitigations:
    - T1486: Behavior Prevention on Endpoint
  - IOCs:
    - url: https://www.securityweek.com/ransomware, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/ransomware-payments-surpassed-4-5-billion-us-treasury/

Entry 33
- [33] Critical Apache Tika Vulnerability Leads to XXE Injection
  - Category: Other
  - Actionability: Informational (20)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/critical, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/critical-apache-tika-vulnerability-leads-to-xxe-injection/

Entry 34
- [34] Exploitation of React2Shell Surges
  - Category: Other
  - Actionability: Medium (40)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/exploitation, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/exploitation-of-react2shell-surges/

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
- [36] JPCERT Confirms Active Command Injection Attacks on Array AG Gateways
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1566 — Phishing 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1593.001: Pre-compromise
  - IOCs:
    - malware: JPCERT, BRICKSTORM, AISURU
    - ip: 9.4.5.8, 9.4.5.9, 194.233.100.138
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/jpcert-confirms-active-command.html

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
- [38] In Other News: X Fined €120 Million, Array Flaw Exploited, New Iranian Backdoor
  - Category: Ransomware
  - Actionability: Medium (50)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/in, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/in-other-news-x-fined-e120-million-array-flaw-exploited-new-iranian-backdoor/

Entry 39
- [39] Cloudflare Outage Caused by React2Shell Mitigations
  - Category: Other
  - Actionability: Medium (45)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/cloudflare, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/cloudflare-outage-caused-by-react2shell-mitigations/

Entry 40
- [40] "Getting to Yes": An Anti-Sales Guide for MSPs
  - Category: Other
  - Actionability: Informational (0)
  - MITRE Techniques:
    - T1059.007 — JavaScript 
    - T1176.001 — Browser Extensions 
    - T1566 — Phishing 
    - T1593.001 — Social Media
  - Mitigations:
    - T1059.007: Behavior Prevention on Endpoint 
    - T1176.001: Limit Software Installation 
    - T1566: Audit 
    - T1593.001: Pre-compromise
  - IOCs:
    - malware: BRICKSTORM, AISURU
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/getting-to-yes-anti-sales-guide-for-msps.html

Entry 41
- [41] CISA Reports PRC Hackers Using BRICKSTORM for Long-Term Access in U.S. Systems
  - Category: Data Theft
  - Actionability: Informational (10)
  - MITRE Techniques:
    - T1213.002 — Sharepoint 
    - T1059.007 — JavaScript 
    - T1584.008 — Network Devices 
    - T1176.001 — Browser Extensions 
    - T1588.006 — Vulnerabilities 
    - T1586.002 — Email Accounts 
    - T1036 — Masquerading 
    - T1076 — Remote Desktop Protocol 
    - T1505.003 — Web Shell 
    - T1090 — Proxy 
    - T1566 — Phishing 
    - T1556.006 — Multi-Factor Authentication 
    - T1592.002 — Software 
    - T1593.001 — Social Media 
    - T1589.001 — Credentials 
    - T1041 — Exfiltration Over C2 Channel
  - Mitigations:
    - T1213.002: Audit 
    - T1059.007: Behavior Prevention on Endpoint 
    - T1584.008: Pre-compromise 
    - T1176.001: Limit Software Installation 
    - T1588.006: Pre-compromise
  - IOCs:
    - malware: BRICKSTORM, UNC5221, AISURU
    - domain: next.js
  - Source: https://thehackernews.com/2025/12/cisa-reports-prc-hackers-using.html

Entry 42
- [42] Lumia Security Raises $18 Million for AI Security and Governance
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/lumia, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/lumia-security-raises-18-million-for-ai-security-and-governance/

Entry 43
- [43] Aisuru Botnet Powers Record DDoS Attack Peaking at 29 Tbps
  - Category: DDoS/Botnet
  - Actionability: Informational (24)
  - Mitigations: --
  - IOCs:
    - url: https://www.securityweek.com/aisuru, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/aisuru-botnet-powers-record-ddos-attack-peaking-at-29-tbps/

Entry 44
- [44] Helmet Security Emerges From Stealth Mode With $9 Million in Funding
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: ai
  - IOCs:
    - url: https://www.securityweek.com/helmet, https://www.securityweek.com
    - domain: securityweek.com
  - Source: https://www.securityweek.com/helmet-security-emerges-from-stealth-mode-with-9-million-in-funding/

Entry 45
- [45] NCSC-2025-0381 [1.00] [M/H] Kwetsbaarheden verholpen in Splunk Enterprise en Splunk Cloud Platform
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - Enablers: cloud
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0381

Entry 46
- [46] NCSC-2025-0380 [1.01] [H/H] Kwetsbaarheden verholpen in React Server Components
  - Category: Other
  - Actionability: Informational (0)
  - Mitigations: --
  - IOCs: --
  - Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0380