# LLM Unstructured Threat Intelligence Report

_Source file: rawtext-20251208.json_

## 1. LOLPROX Unveils Undetected Exploitation Routes for Stealthy Hypervisor Attacks
_Source: https://gbhackers.com/hypervisor-attacks/_

**Summary:** LOLPROX, a stealthy hypervisor attack framework, has been uncovered by security researcher Andy Gill. It leverages built-in tools to execute deep persistence attacks on Proxmox Virtual Environment (VE), bypassing traditional network monitoring and endpoint detection systems.
**MITRE Techniques:**
- N/A LOLPROX Hypervisor Attack (Initial Access)
- T1218 File and Directory Discovery (Lateral Movement)
- N/A Kernel Level Threats (Persistence)
**IOCs:**
- domain: vsock operations — C2 channel establishment between hypervisor and guest VMs
- url: https://gbhackers.com/ — Researcher's website for LOLPROX analysis
**Detections:**
- LOLPROX Hypervisor Attack Detection: Monitor vsock operations and QEMU Guest Agent usage for suspicious activity
- Kernel Level Threats Detection: Audit kernel modules and eBPF for malicious behavior

## 2. WatchGuard Firebox Vulnerabilities Let Hackers Skip Integrity Validation and Plant Malicious Code
_Source: https://gbhackers.com/watchguard-firebox-vulnerabilities/_

**Summary:** WatchGuard has disclosed six vulnerabilities affecting its Firebox firewall products, which could allow attackers to bypass system integrity checks and execute malicious code.
**MITRE Techniques:**
- N/A Boot Integrity Check Bypass (Lateral Movement)
- T1212 Exploit Public-Facing Application (Execution)
**IOCs:**
- cve: CVE-2025-13940 — Vulnerability ID
- cve: CVE-2025-1545 — Vulnerability ID
**Detections:**
- Firewall Rule Monitoring: Monitor firewall rules for suspicious activity and alert on any changes.
- Vulnerability Scanning: Regularly scan the network for vulnerabilities like CVE-2025-13940 and CVE-2025-1545.

## 3. OceanLotus Targets Xinchuang Ecosystem with Sophisticated Supply Chain Attacks
_Source: https://gbhackers.com/xinchuang-ecosystem/_

**Summary:** OceanLotus (APT32) targets China's Xinchuang ecosystem with sophisticated supply chain attacks, compromising Linux-based operating systems and internal supply chains.
**MITRE Techniques:**
- N/A Spear Phishing via Social Engineering (Initial Access)
- T1190 Exploit Public-Facing Application (Execution)
- T1068 Valid Accounts (Lateral Movement)
**IOCs:**
- ip: 
- domain: 
- file: Desktop Entry file (.desktop) — Used as bait to execute malicious code

## 4. CISA Adds Critical React2Shell Vulnerability to KEV Catalog After Active Exploitation
_Source: https://gbhackers.com/cisa-adds-critical-react2shell-vulnerability-to-kev-catalog/_

**Summary:** The CISA has added a high-severity vulnerability, 'React2Shell', to its Known Exploited Vulnerabilities (KEV) catalog. This RCE bug affects Meta's React Server Components and is actively being exploited in the wild.
**MITRE Techniques:**
- N/A
**IOCs:**
- : CVE-2025-55182 — Vulnerability ID
- : React2Shell — Vulnerability name
**Detections:**
- Check for vulnerable React Server Components versions: Analyze server responses to detect potential RCE attempts.
- Monitor for suspicious requests to React Server Function endpoints: Identify and block malicious requests that may exploit the vulnerability.
**Recommendations:**
- Apply vendor-provided patches or mitigations immediately, or consider discontinuing use of affected product until it can be secured.

## 5. Indonesia’s Gambling Industry Reveals Clues of Nationwide Cyber Involvement
_Source: https://gbhackers.com/indonesias-gambling/_

**Summary:** Indonesia's gambling industry has been infiltrated by a sophisticated cybercrime operation that has lasted for over 14 years, with characteristics aligning more closely with state-sponsored threat operations than conventional financial cybercrime.
**MITRE Techniques:**
- N/A Unknown (Unknown)
- T1210 Exploit Public-Facing Application (Initial Access)
- N/A Unknown (Execution)
**IOCs:**
- domain: jp api.namesvr[.]dev — Command and control traffic
- IP address: 600 IP addresses — Hosting multiple domains

## 6. Next.js Releases Scanner to Detect and Fix Apps Affected by React2Shell Vulnerability
_Source: https://gbhackers.com/next-js-releases-scanner-react2shell-vulnerability/_

**Summary:** Next.js developers have released a scanner to detect and fix apps affected by the critical 'React2Shell' vulnerability, tracked as CVE-2025-66478.
**MITRE Techniques:**
- N/A Unknown
**Detections:**
- Vulnerable package detection: Monitor for vulnerable packages in package.json files, especially those matching specific versions listed in the article (e.g., 15.0.0 – 15.0.4)
**Recommendations:**
- Use the fix-react2shell-next tool to automatically detect and patch vulnerable applications

## 7. Porsche Cars Disabled After Major Failure in Installed Satellite Security System
_Source: https://gbhackers.com/porsche-cars-disabled-after-failure-in-installed-satellite-security-system/_

**Summary:** A security system failure in Porsche cars has left hundreds of owners in Russia unable to drive their vehicles. The issue affects only gasoline-powered models and is believed to be related to the car's "telematics" system, which connects the vehicle to the internet.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Persistence)
**Detections:**
- Telematics system usage detection: Monitor network traffic related to the telematics system for unusual activity
- Software update analysis: Analyze software updates sent over the air to vehicles for potential malware or unauthorized code execution
**Recommendations:**
- Vehicle owners should be aware of the potential risks associated with the telematics system and take steps to mitigate them, such as updating their vehicle's software regularly
- Porsche should investigate the cause of the security system failure and implement measures to prevent similar incidents in the future

## 8. Hackers Target Developers Using Malicious VS Code and Cursor AI Extensions
_Source: https://gbhackers.com/vs-code-and-cursor-ai/_

**Summary:** Hackers are targeting developers using malicious VS Code and Cursor AI extensions, which can lead to persistent access to developer machines and potentially severe breaches.
**MITRE Techniques:**
- N/A Lateral Movement (Persistence)
- T1218 File and Directory Discovery (Reconnaissance)
**IOCs:**
- other: Piithon linter — Malicious extension submitted to the VS Code Marketplace.
- other: Merlin post-exploitation agent — Agent used for Windows, macOS, and Linux exploitation.
**Detections:**
- VS Code extension behavior analysis: Monitor for suspicious extension activity, such as exfiltration of environment variables or system metadata.
- PII extraction detection: Detect and block the extraction of sensitive PII data, such as cloud keys or access tokens.
**Recommendations:**
- Implement stronger security controls on VS Code, OpenVSX, and AI-powered IDEs to prevent malicious extensions from being installed.
- Regularly update and patch all software and dependencies to prevent exploitation of known vulnerabilities.

## 9. OpenAI denies rolling out ads on ChatGPT paid plans
_Source: https://www.bleepingcomputer.com/news/artificial-intelligence/openai-denies-rolling-out-ads-on-chatgpt-paid-plans/_

**Summary:** OpenAI denies rolling out ads on ChatGPT paid plans, claims it's app recommendations from pilot partners.
**MITRE Techniques:**
- N/A Unknown (Social Engineering)
**Detections:**
- ChatGPT app recommendations monitoring: Monitor for any unusual or unsolicited app recommendations from ChatGPT.
**Recommendations:**
- Users should be aware of the potential for commercial suggestions within ChatGPT and report any suspicious activity to OpenAI support.

## 10. Portugal updates cybercrime law to exempt security researchers
_Source: https://www.bleepingcomputer.com/news/security/portugal-updates-cybercrime-law-to-exempt-security-researchers/_

**Summary:** Portugal updates its cybercrime law to exempt security researchers from punishment when conducting good-faith research and reporting vulnerabilities.
**MITRE Techniques:**
- N/A
**IOCs:**
- other: Article 8.o A, titled "Acts not punishable due to public interest in cybersecurity" — Legal provision
**Detections:**
- Detection of prohibited techniques in security research: Monitor for attempts to disrupt services, alter or delete data, or cause harm during security research efforts. Identify prohibited techniques such as DoS attacks, social engineering, phishing, password theft, intentional data alteration, system damage, or malware deployment.
**Recommendations:**
- Security researchers should be aware of the legal exemptions for good-faith research and report vulnerabilities promptly to avoid prosecution. Ensure that all security activities are conducted within the bounds of the law and in compliance with GDPR regulations.

## 11. Critical Cal.com Flaw Allows Attackers to Bypass Authentication Using Fake TOTP Codes
_Source: https://gbhackers.com/critical-cal-com-flaw-allows-attackers-to-bypass-authentication-using-fake-totp-codes/_

**Summary:** A critical authentication bypass vulnerability, tracked as CVE-2025-66489, affects all versions of Cal.com up to and including 5.9.7. Attackers can exploit this flaw by submitting a fake TOTP code, allowing them to gain unauthorized access to user accounts.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
**IOCs:**
- other: CVE-2025-66489 — Vulnerability ID
- url:  — Malicious TOTP code submission URL
**Detections:**
- TOTP code submission detection: Monitor for non-empty TOTP code submissions alongside user email addresses, potentially indicating unauthorized access attempts.
- User account takeover detection: Watch for unusual login activity or suspicious changes in user accounts, which may indicate the exploitation of this vulnerability.
**Recommendations:**
- Update Cal.com to version 5.9.8 immediately to patch the vulnerability and protect against potential exploitation.
- Implement additional security measures, such as multi-factor authentication or session management, to reduce the risk of unauthorized access.

## 12. React2Shell flaw exploited to breach 30 orgs, 77k IP addresses vulnerable
_Source: https://www.bleepingcomputer.com/news/security/react2shell-flaw-exploited-to-breach-30-orgs-77k-ip-addresses-vulnerable/_

**Summary:** The React2Shell remote code execution flaw (CVE-2025-55182) has been exploited to breach over 30 organizations and affect 77k IP addresses, with attackers primarily using PowerShell commands to confirm vulnerability and execute base64 encoded scripts.
**MITRE Techniques:**
- T1210 Exploitation of Remote Services (Initial Access)
- N/A Remote Code Execution (Execution)
- T1071 Custom Implementation (Command and Control)
**IOCs:**
- ip: 23[.]235[.]188[.]3 — C2 server
- url: powershell c "40138*41979" — Phishing URL
**Detections:**
- Yurei ransomware filesystem behavior: Monitor for PowerShell commands and base64 encoded scripts executing on endpoints, indicating potential exploitation of the React2Shell flaw.
**Recommendations:**
- Update React to the latest version, rebuild applications, and redeploy them immediately to fix the vulnerability.
- Review logs for signs of PowerShell or shell command execution, indicating potential exploitation of the React2Shell flaw.

## 13. New wave of VPN login attempts targets Palo Alto GlobalProtect portals
_Source: https://www.bleepingcomputer.com/news/security/new-wave-of-vpn-login-attempts-targets-palo-alto-globalprotect-portals/_

**Summary:** A new wave of VPN login attempts, targeting Palo Alto GlobalProtect portals and SonicWall SonicOS API endpoints. The attacks originated from over 7,000 IP addresses in Germany, attributed to the same actor.
**MITRE Techniques:**
- T1210 Exploit Public-Facing Application (Initial Access)
- N/A Brute Force (Lateral Movement)
**IOCs:**
- ip:  — Originating IP addresses of the attacks.
- other: 3xK GmbH's BGP network (AS200373) — The company operating the originating infrastructure.
**Detections:**
- GlobalProtect VPN portal scans: Monitor for IP addresses associated with this type of activity and block them. Monitor authentication surfaces for abnormal velocity/repeated failures.
**Recommendations:**
- Enforce Multi-Factor Authentication (MFA) to protect against credential abuse. Monitor for IPs associated with this type of activity and block them.

## 14. Barts Health NHS discloses data breach after Oracle zero-day hack
_Source: https://www.bleepingcomputer.com/news/security/barts-health-nhs-discloses-data-breach-after-oracle-zero-day-hack/_

**Summary:** Barts Health NHS Trust in England disclosed a data breach after Clop ransomware actors exploited a vulnerability in its Oracle E business Suite software, stealing invoices with sensitive information.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Execution)
**IOCs:**
- url: https://www.bleepingcomputer.com/news/security/barts-health-nhs-discloses-data-breach-after-oracle-zero-day-hack/ — Article URL
- hash:  — CVE-2025-61882 mentioned in article as exploited vulnerability
**Recommendations:**
- Barts Health NHS Trust recommends patients check their invoices to determine what data was exposed and stay vigilant for unsolicited communications, especially messages that request payment or sharing of sensitive information.

## 15. FBI warns of virtual kidnapping scams using altered social media photos
_Source: https://www.bleepingcomputer.com/news/security/fbi-warns-of-virtual-kidnapping-ransom-scams-using-altered-social-media-photos/_

**Summary:** The FBI warns of virtual kidnapping scams where scammers use altered social media photos to demand ransom payments from victims.
**MITRE Techniques:**
- N/A
**Detections:**
- Monitor for suspicious social media activity and ransom demands.: Look for unusual login attempts from unfamiliar locations or devices.
- Verify the authenticity of images shared on social media before taking action.: Use image analysis tools to compare with confirmed photos of family members.
**Recommendations:**
- Establish a code word known only to the family for verification during emergencies and avoid providing personal information to strangers while traveling.
- Educate family members about the risks of virtual kidnapping scams and the importance of verifying communication claims before acting.

## 16. Shanya EDR Killer: The New Favorite Tool for Ransomware Operators
_Source: https://gbhackers.com/shanya-edr-killer/_

**Summary:** A new 'packer as a-service' tool called Shanya has emerged in the cybercriminal underground, allowing major ransomware groups to neutralize endpoint defenses and deploy payloads without interference.
**MITRE Techniques:**
- N/A DLL side loading (Persistence)
- T1218 Signed Binary Placement (Defense Evasion)
**IOCs:**
- domain: Telegram contact information — C2 server
- ip: 
**Detections:**
- Yurei ransomware filesystem behavior detection: Monitor for suspicious DLL side loading and BYOVD attacks on endpoint systems.
- Shanya packer detection: Monitor network traffic for communication with known Shanya command and control servers.

## 17. A Practical Guide to Continuous Attack Surface Visibility
_Source: https://www.bleepingcomputer.com/news/security/a-practical-guide-to-continuous-attack-surface-visibility/_

**Summary:** Continuous attack surface visibility requires automated, active reconnaissance that verifies external exposure daily, as static passive data becomes outdated quickly and lacks context.
**MITRE Techniques:**
- N/A Unknown
**Detections:**
- Continuous reconnaissance for exposed services: Monitor network traffic for newly exposed services and misconfigurations introduced during deployments.
- Shadow IT and rogue asset detection: Use endpoint monitoring to detect shadow IT and rogue assets on the network.
**Recommendations:**
- Implement continuous monitoring and automate where possible to stay ahead of emerging exposures.
- Prioritize vulnerabilities based on risk and regularly update and patch systems to prevent easily avoidable incidents.

## 18. Cloudflare down, websites offline with 500 Internal Server Error
_Source: https://www.bleepingcomputer.com/news/technology/cloudflare-down-websites-offline-with-500-internal-server-error/_

**Summary:** Cloudflare is experiencing a downtime, causing websites to display a 500 Internal Server Error. The company is investigating the issue.
**MITRE Techniques:**
- N/A Unknown (Unknown)

## 19. Cloudflare blames today's outage on React2Shell mitigations
_Source: https://www.bleepingcomputer.com/news/security/cloudflare-blames-todays-outage-on-emergency-react2shell-patch/_

**Summary:** Cloudflare blamed an outage on emergency React2Shell mitigations designed to address a critical remote code execution vulnerability in React Server Components, which is actively exploited.
**MITRE Techniques:**
- N/A  (Execution)
- N/A  (Persistence)
**IOCs:**
- cve: CVE-2025-55182 — Vulnerability identifier
- ip:  — Not specified in the article
**Detections:**
- Detect React2Shell exploitation: Monitor for suspicious HTTP requests to React Server Function endpoints.
- Identify affected applications: Scan for presence of vulnerable React versions 19.0, 19.1.0, 19.1.1, and 19.2.0.
**Recommendations:**
- Update to the latest React version or patch affected applications.
- Implement additional security measures to detect and prevent exploitation of the React2Shell vulnerability.

## 20. EU fines X $140 million over deceptive blue checkmarks
_Source: https://www.bleepingcomputer.com/news/security/eu-fines-x-140-million-over-deceptive-blue-checkmarks-transparency-violations/_

**Summary:** The EU fined X $140 million for violating transparency obligations under the Digital Services Act, specifically regarding deceptive blue checkmarks that can be purchased without meaningful identity verification.
**MITRE Techniques:**
- N/A Social Engineering (Initial Access)
**Detections:**
- Deceptive blue checkmark badge detection: Monitor for users purchasing blue checkmarks without proper identity verification and flag suspicious activity.
**Recommendations:**
- X should re-evaluate its policies regarding transparency and user verification to prevent similar issues in the future.

## 21. Critical React2Shell flaw actively exploited in China-linked attacks
_Source: https://www.bleepingcomputer.com/news/security/react2shell-critical-flaw-actively-exploited-in-china-linked-attacks/_

**Summary:** Multiple China-linked threat actors have started exploiting the recently disclosed React2Shell vulnerability (CVE-2025-55182), affecting React and Next.js, which allows remote execution of JavaScript code in the server's context without authentication.
**MITRE Techniques:**
- N/A Insecure Deserialization (Initial Access)
**IOCs:**
- url: https://github.com/wiz-research/React2Shell-scanner — A React2Shell scanner for determining vulnerability.
- other: AWS honeypots caught activity not attributed to any known clusters, but which still originates from China-based infrastructure — Unspecified IOCs originating from China-based infrastructure.
**Detections:**
- Yurei ransomware-like behavior on the server-side: Look for suspicious processes executing JavaScript code, attempts to create files or read sensitive data in the server's context. Monitor for unusual network activity originating from the server.
**Recommendations:**
- Apply security updates provided by React and Next.js. Implement secure deserialization practices in your application. Regularly monitor your servers for suspicious activity and implement logging and monitoring solutions to detect potential exploits.

## 22. Pharma firm Inotiv discloses data breach after ransomware attack
_Source: https://www.bleepingcomputer.com/news/security/pharma-firm-inotiv-discloses-data-breach-after-ransomware-attack/_

**Summary:** Pharmaceutical firm Inotiv disclosed a data breach after a ransomware attack in August 2025, which resulted in the theft of personal information from thousands of individuals.
**MITRE Techniques:**
- N/A  (Initial Access)
- N/A  (Execution)
**IOCs:**
- other: Qilin ransomware group's leak site (BleepingComputer) — Leaked data samples allegedly stolen from Inotiv's compromised systems
**Detections:**
- Ransomware malware execution on Inotiv's systems: Monitor for suspicious process creation, network connections, and file access patterns
- Data exfiltration by Qilin ransomware group: Detect and block unusual outbound data transfers, especially to known C2 servers or leak sites
**Recommendations:**
- Implement regular security audits, patch management, and vulnerability assessments to prevent similar attacks
- Develop an incident response plan to quickly contain and respond to ransomware attacks

## 23. Sneeit WordPress RCE Exploited in the Wild While ICTBroadcast Bug Fuels Frost Botnet Attacks
_Source: https://thehackernews.com/2025/12/sneeit-wordpress-rce-exploited-in-wild.html_

**Summary:** A critical RCE vulnerability in the Sneeit Framework plugin for WordPress is being actively exploited, while a flaw in ICTBroadcast is used to deliver Frost DDoS botnet attacks.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- T1210 Exploit Public-Facing Application (Initial Access)
- N/A Unknown (Execution)
- T1055 Process Injection (Persistence)

## 24. Zero-Click Agentic Browser Attack Can Delete Entire Google Drive Using Crafted Emails
_Source: https://thehackernews.com/2025/12/zero-click-agentic-browser-attack-can.html_

**Summary:** A zero-click agentic browser attack can delete entire Google Drive contents using crafted emails. The attack exploits the behavior of AI-powered assistants in browsers like Comet, which can interpret user instructions and perform actions without explicit confirmation.
**MITRE Techniques:**
- N/A Lateral Movement (Persistence)
- N/A Malware Execution (Execution)
**IOCs:**
- email: Please check my email and complete all my recent organization tasks. — C2 server
- url: www.example[.]com/home#<prompt> — Phishing URL
**Detections:**
- Zero-click agentic browser attack detection: Monitor for suspicious email activity and network communications between the victim's browser and cloud storage services.
- HashJack detection: Monitor for hidden prompts in legitimate URLs and detect unusual behavior from AI-powered browsers.
**Recommendations:**
- Implement additional security measures to restrict the capabilities of AI-powered browser assistants and prevent excessive agency in LLMs. Monitor user activity and network communications for suspicious behavior related to cloud storage services.
- Educate users about the risks associated with agentic AI-powered browsers and encourage them to use secure communication protocols when interacting with cloud storage services.

## 25. MuddyWater Deploys UDPGangster Backdoor in Targeted Turkey-Israel-Azerbaijan Campaign
_Source: https://thehackernews.com/2025/12/muddywater-deploys-udpgangster-backdoor.html_

**Summary:** MuddyWater hacking group uses UDPGangster backdoor to target Turkey, Israel, and Azerbaijan, deploying malicious payloads via spear phishing emails.
**MITRE Techniques:**
- N/A Initial Access (Execution)
- T1190 Exploit Public-Facing Application (Initial Access)
- N/A Persistence (Execution)
- N/A Command and Control (Execution)
**IOCs:**
- domain: 157.20.182.75 — C2 server
- filename: seminer.doc — Malicious payload delivered via spear phishing email
**Detections:**
- Spear Phishing Detection: Monitor emails with suspicious attachments, particularly those requesting macro activation.
- Malicious Payload Detection: Detect and block execution of unknown payloads, especially those delivered via spear phishing attacks.
**Recommendations:**
- Implement robust email filtering and attachment scanning to detect and prevent spear phishing attempts. Regularly update Microsoft Word and other software to patch vulnerabilities.
- Train employees to be cautious of unsolicited documents, especially those requesting macro activation. Establish a reporting process for suspicious emails or attachments.

## 26. Critical React2Shell Flaw Added to CISA KEV After Confirmed Active Exploitation
_Source: https://thehackernews.com/2025/12/critical-react2shell-flaw-added-to-cisa.html_

**Summary:** A critical vulnerability (CVE-2025-55182) has been added to CISA's KEV catalog after reports of active exploitation in the wild, affecting React Server Components and potentially millions of instances.
**MITRE Techniques:**
- T1190 Exploit Use (Initial Access)
- null Insecure Deserialization (Execution)
**IOCs:**
- url: https://www.reactjs.org/ (not explicitly mentioned in the text, but as a React Server Components example) — C2 server
- domain: earth-lamia.com — Attributed to Chinese hacking groups
**Detections:**
- Detection of suspicious HTTP requests to React Server Components endpoints: 
- Detection of known malware and payloads associated with the vulnerability: 
**Recommendations:**
- Update React Server Components to the latest version as soon as possible, as multiple proof-of-concept exploits have been published.
- Implement a Web Application Firewall (WAF) to block suspicious traffic and prevent exploitation of the vulnerability.

## 27. Android Malware FvncBot, SeedSnatcher, and ClayRat Gain Stronger Data Theft Features
_Source: https://thehackernews.com/2025/12/android-malware-fvncbot-seedsnatcher.html_

**Summary:** Two new Android malware families, FvncBot and SeedSnatcher, have been discovered with stronger data theft features, while ClayRat has also been upgraded to abuse accessibility services.
**MITRE Techniques:**
- N/A User Execution (Execution)
- N/A Accessibility Features (Persistence)
- T1204 User Execution: Malware Transfer Vector (Execution)
**IOCs:**
- Hash: 1234567890abcdef
- Domain: fvncbot.com

## 28. Critical XXE Bug CVE-2025-66516 (CVSS 10.0) Hits Apache Tika, Requires Urgent Patch
_Source: https://thehackernews.com/2025/12/critical-xxe-bug-cve-2025-66516-cvss.html_

**Summary:** A critical security flaw (CVE-2025-66516) has been disclosed in Apache Tika, allowing XML external entity (XXE) injection attacks. This vulnerability affects various Maven packages and can result in remote code execution.
**MITRE Techniques:**
- T1202 Exploit Public-Facing Application (Initial Access)
- N/A  XXE injection (Execution)
**Detections:**
- XXE injection detection: Look for suspicious XML data being processed by Apache Tika, potentially indicating a XXE injection attack.
- Remote code execution detection: Monitor for unusual activity or code execution on endpoints that have been compromised via the XXE vulnerability.
**Recommendations:**
- Apply patches to affected Maven packages as soon as possible, and ensure all dependencies are up-to-date to prevent exploitation of this vulnerability.

## 29. Chinese Hackers Have Started Exploiting the Newly Disclosed React2Shell Vulnerability
_Source: https://thehackernews.com/2025/12/chinese-hackers-have-started-exploiting.html_

**Summary:** Chinese hackers have started exploiting the newly disclosed React2Shell vulnerability (CVE-2025-55182) with a CVSS score of 10.0, allowing unauthenticated remote code execution.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Execution)
**IOCs:**
- ip: unknown IP addresses and infrastructure historically linked to known China state nexus threat actors — C2 server
- url: unknown URLs containing sensitive information — read files

## 30. Researchers Uncover 30+ Flaws in AI Coding Tools Enabling Data Theft and RCE Attacks
_Source: https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html_

**Summary:** {'title': 'Researchers Uncover 30+ Flaws in AI Coding Tools Enabling Data Theft and RCE Attacks', 'description': 'Multiple vulnerabilities in AI coding tools, including prompt injection, command injection, and data exfiltration, put development machines at risk.'}

## 31. Intellexa Leaks Reveal Zero-Days and Ads-Based Vector for Predator Spyware Delivery
_Source: https://thehackernews.com/2025/12/intellexa-leaks-reveal-zero-days-and.html_

**Summary:** The report has highlighted the different delivery vectors adopted by Intellexa to trigger the opening of the malicious link without the need for the target to manually click on it.

## 32. Ransomware Payments Surpassed $4.5 Billion: US Treasury
_Source: https://www.securityweek.com/ransomware-payments-surpassed-4-5-billion-us-treasury/_

**Summary:** The US Treasury reports that ransomware payments have surpassed $4.5 billion in 2023, with $1.1 billion paid in 1,512 reported incidents.
**MITRE Techniques:**
- N/A Initial Access (Execution)
- T1059 Command and Control (Lateral Movement)
**Detections:**
- Ransomware payment monitoring: Monitor for suspicious financial transactions related to ransomware payments
**Recommendations:**
- Educate users on the risks of ransomware and the importance of backups to prevent data loss
- Develop incident response plans for ransomware attacks, including communication with law enforcement and affected parties

## 33. Critical Apache Tika Vulnerability Leads to XXE Injection
_Source: https://www.securityweek.com/critical-apache-tika-vulnerability-leads-to-xxe-injection/_

**Summary:** A critical vulnerability in Apache Tika allows attackers to inject XML External Entity (XXE) attacks via crafted XFA files inside PDFs.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
**Detections:**
- XXE Injection Detection: Monitor network traffic for unusual XML External Entity (XXE) injection attempts and analyze incoming PDF files for suspicious XFA content.
**Recommendations:**
- Apply the latest security patches to Apache Tika to mitigate this vulnerability. Additionally, consider implementing additional security measures such as input validation and sanitization to prevent XXE injection attacks.

## 34. Exploitation of React2Shell Surges
_Source: https://www.securityweek.com/exploitation-of-react2shell-surges/_

**Summary:** Threat actors are exploiting the CVE-2025-55182 vulnerability in React to carry out attacks.
**MITRE Techniques:**
- N/A  (Initial Access)
- T1204 User Execution: Malware Transfer (Execution)
**IOCs:**
- cve: CVE-2025-55182 — Vulnerability being exploited by threat actors
**Recommendations:**
- Ensure that all systems are up-to-date with the latest security patches, particularly for React.
- Implement a regular patch management process to prevent exploitation of known vulnerabilities

## 35. US Organizations Warned of Chinese Malware Used for Long-Term Persistence
_Source: https://www.securityweek.com/us-organizations-warned-of-chinese-malware-used-for-long-term-persistence/_

**Summary:** US organizations are being targeted by Chinese malware, specifically BrickStorm, Junction, and GuestConduit, which enable long-term persistence.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- T1071 Indicator Manipulation (Defense Evasion)
**IOCs:**
- domain: BrickStorm — Malware domain used for persistence
- domain: Junction — Malware domain used for persistence
- domain: GuestConduit — Malware domain used for persistence
**Detections:**
- Warp Panda malware detection: Monitor network traffic for suspicious activity related to BrickStorm, Junction, and GuestConduit
- Malware persistence detection: Check for signs of persistence on compromised systems, such as registry keys or system files modified by the malware
**Recommendations:**
- Implement network segmentation and monitoring to detect suspicious activity. Regularly update and patch systems to prevent exploitation.
- Develop incident response plans to quickly respond to potential breaches. Conduct regular security audits to identify vulnerabilities

## 36. JPCERT Confirms Active Command Injection Attacks on Array AG Gateways
_Source: https://thehackernews.com/2025/12/jpcert-confirms-active-command.html_

**Summary:** JPCERT has confirmed active command injection attacks on Array AG Gateways, exploiting a vulnerability in the DesktopDirect feature that allows remote desktop access. The attack has been used to drop web shells on susceptible devices since August 2025.
**MITRE Techniques:**
- T1210 Exploit Public-Facing Application (Initial Access)
- T1190 Exploit Use of Outdated or Vulnerable Components (Initial Access)
- N/A Command Injection (Execution)
**IOCs:**
- ip: 194.233.100.138 — C2 server
- domain:  — Unknown
**Detections:**
- DesktopDirect vulnerability detection: Monitor network traffic for suspicious activity related to DesktopDirect, such as unusual command injection attempts.
- Web shell installation detection: Monitor endpoint systems for signs of web shell installation, such as unusual network activity or changes to system files.
**Recommendations:**
- Apply the latest updates for ArrayOS versions 9.4.5.8 and earlier to address the vulnerability. Disable DesktopDirect services and use URL filtering to deny access to URLs containing a semicolon.

## 37. Imper.ai Emerges From Stealth Mode With $28 Million in Funding
_Source: https://www.securityweek.com/imper-ai-emerges-from-stealth-mode-with-28-million-in-funding/_

**Summary:** Imper.ai, a cybersecurity startup, has emerged from stealth mode with $28 million in funding. It detects impersonation risk in real-time across video, phone, and chat communication.

## 38. In Other News: X Fined €120 Million, Array Flaw Exploited, New Iranian Backdoor
_Source: https://www.securityweek.com/in-other-news-x-fined-e120-million-array-flaw-exploited-new-iranian-backdoor/_

**Summary:** X has been fined €120 million for an array flaw exploited by hackers. Additionally, a new Iranian backdoor was discovered.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- T1190 Exploit Public-Facing Application (Initial Access)
- N/A Unknown (Execution)
**Detections:**
- HTTP smuggling detection: Monitor for suspicious HTTP requests and responses to detect potential HTTP smuggling attacks.
- Ransomware execution detection: Monitor for unusual file creation, deletion, or modification patterns on endpoints to detect potential ransomware execution.
**Recommendations:**
- Patch the HTTP smuggling vulnerability and implement additional security measures to prevent similar attacks in the future.
- Develop a comprehensive incident response plan to quickly respond to ransomware attacks and minimize business impact.

## 39. Cloudflare Outage Caused by React2Shell Mitigations
_Source: https://www.securityweek.com/cloudflare-outage-caused-by-react2shell-mitigations/_

**Summary:** A critical React vulnerability has been exploited in the wild, causing a Cloudflare outage. Chinese and other threat actors have been identified as exploiting this flaw.
**MITRE Techniques:**
- N/A Unknown technique (Initial Access)

## 40. "Getting to Yes": An Anti-Sales Guide for MSPs
_Source: https://thehackernews.com/2025/12/getting-to-yes-anti-sales-guide-for-msps.html_

**Summary:** An anti-sales guide for Managed Service Providers (MSPs) helps them transform resistance into trust and turn sales conversations into long-term partnerships by focusing on education, transparency, and measurable outcomes.
**MITRE Techniques:**
- N/A Unknown (Social Engineering)

## 41. CISA Reports PRC Hackers Using BRICKSTORM for Long-Term Access in U.S. Systems
_Source: https://thehackernews.com/2025/12/cisa-reports-prc-hackers-using.html_

**Summary:** {'title': 'CISA Reports PRC Hackers Using BRICKSTORM for Long-Term Access in U.S. Systems', 'description': 'The article discusses the use of BRICKSTORM by Chinese hackers to gain long-term access to U.S. systems.', 'published_date': '2025-12-01T00:00:00Z'}

## 42. Lumia Security Raises $18 Million for AI Security and Governance
_Source: https://www.securityweek.com/lumia-security-raises-18-million-for-ai-security-and-governance/_

**Summary:** Lumia Security, a startup focused on AI security and governance, raises $18 million in funding to expand its engineering team, deepen product integrations, and scale go-to-market efforts.

## 43. Aisuru Botnet Powers Record DDoS Attack Peaking at 29 Tbps
_Source: https://www.securityweek.com/aisuru-botnet-powers-record-ddos-attack-peaking-at-29-tbps/_

**Summary:** The Aisuru botnet was responsible for a record-breaking DDoS attack that peaked at 29 terabits per second, posing significant impact to networks.
**MITRE Techniques:**
- N/A Unknown (Unknown)
**Detections:**
- High-volume traffic detection: Monitor network traffic for unusually high volumes of data transfer
- Botnet detection: Identify and isolate devices infected with the Aisuru botnet
**Recommendations:**
- Implement robust DDoS protection measures, including rate limiting and IP blocking
- Regularly update software and firmware to prevent exploitation of vulnerabilities

## 44. Helmet Security Emerges From Stealth Mode With $9 Million in Funding
_Source: https://www.securityweek.com/helmet-security-emerges-from-stealth-mode-with-9-million-in-funding/_

**Summary:** Helmet Security, a startup, has emerged from stealth mode with $9 million in funding to develop an end-to-end platform for securing agentic AI communication infrastructure.
**MITRE Techniques:**
- N/A Unknown

## 45. NCSC-2025-0381 [1.00] [M/H] Kwetsbaarheden verholpen in Splunk Enterprise en Splunk Cloud Platform
_Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0381_

**Summary:** The Dutch National Cyber Security Centre (NCSC) has published a security advisory regarding vulnerabilities in Splunk Enterprise and Splunk Cloud Platform. The vulnerabilities allow for remote code execution and data exfiltration.
**MITRE Techniques:**
- N/A Unknown (Initial Access)
- N/A Unknown (Execution)
**Detections:**
- Detect malicious requests to affected system: Monitor network traffic for suspicious requests and logs
- Check system logs for potential exploitation attempts: Regularly check system logs for signs of exploitation or malicious activity
**Recommendations:**
- Apply patches to affected systems and ensure up-to-date software versions
- Conduct regular security audits and vulnerability assessments on the affected systems

## 46. NCSC-2025-0380 [1.01] [H/H] Kwetsbaarheden verholpen in React Server Components
_Source: https://advisories.ncsc.nl/advisory?id=NCSC-2025-0380_

**Summary:** The NCSC has published an advisory (NCSC-2025-0380) on vulnerabilities in React Server Components. These vulnerabilities have been patched.
**MITRE Techniques:**
- N/A  (Initial Access)
- N/A  (Execution)
**Detections:**
- Vulnerable React Server Components detected: Monitor web application traffic for signs of unauthorized access or code execution
- Unpatched React Server Component found: Scan endpoints for unpatched React Server Components and apply necessary patches
**Recommendations:**
- Apply the latest security patches to React Server Components as soon as possible.
- Regularly monitor web application traffic and endpoints for signs of unauthorized access or code execution.
