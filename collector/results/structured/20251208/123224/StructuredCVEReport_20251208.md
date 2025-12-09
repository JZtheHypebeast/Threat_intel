# Structured CVE Intelligence Report

**Generated:** 2025-12-08 12:34 UTC  

**Window:** Last 75 hours

---

## Critical CVEs (CVSS ≥ 8.5)

### CVE-2025-66570
**Vendor:** docker
**CVSS Base Score:** 10.0
**Severity:** CRITICAL
**Published:** 2025-12-05T19:15:51.923000+00:00
**Description:** cpp-httplib is a C++11 single-file header-only cross platform HTTP/HTTPS library. Prior to 0.27.0, a vulnerability allows attacker-controlled HTTP headers to influence server-visible metadata, logging, and authorization decisions. An attacker can inject headers named REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT that are parsed into the request header multimap via read_headers() in httplib.h (h...

---

## Interesting CVEs (CVSS 6.5–8.5)

### CVE-2025-46603
**Vendor:** Dell
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-12-05T19:15:48.233000+00:00
**Description:** Dell CloudBoost Virtual Appliance, versions 19.13.0.0 and prior, contains an Improper Restriction of Excessive Authentication Attempts vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability, leading to unauthorized access....

---

### CVE-2025-66623
**Vendor:** Kubernetes
**CVSS Base Score:** 7.4
**Severity:** HIGH
**Published:** 2025-12-05T19:15:52.910000+00:00
**Description:** Strimzi provides a way to run an Apache Kafka cluster on Kubernetes or OpenShift in various deployment configurations. From 0.47.0 and prior to 0.49.1, in some situations, Strimzi creates an incorrect Kubernetes Role which grants the Apache Kafka Connect and Apache Kafka MirrorMaker 2 operands the GET access to all Kubernetes Secrets that exist in the given Kubernetes namespace. The issue is fixed...

---

## Recently Modified CVEs (Last 75h)

### CVE-2017-20005
**Vendor:** NetApp
**CVSS Base Score:** 9.8
**Severity:** CRITICAL
**Published:** 2021-06-06T22:15:08.417000+00:00
**Last Modified:** 2025-12-05T15:15:49.443000+00:00
**Description:** NGINX before 1.13.6 has a buffer overflow for years that exceed four digits, as demonstrated by a file with a modification date in 1969 that causes an integer overflow (or a false modification date far in the future), when encountered by the autoindex module....

---

### CVE-2024-28111
**Vendor:** Microsoft
**CVSS Base Score:** 6.5
**Severity:** MEDIUM
**Published:** 2024-03-06T22:15:57.780000+00:00
**Last Modified:** 2025-12-05T16:25:22.687000+00:00
**Description:** Canarytokens helps track activity and actions on a network. Canarytokens.org supports exporting the history of a Canarytoken's incidents in CSV format. The generation of these CSV files is vulnerable to a CSV Injection vulnerability. This flaw can be used by an attacker who discovers an HTTP-based Canarytoken to target the Canarytoken's owner, if the owner exports the incident history to CSV and o...

---

### CVE-2023-32969
**Vendor:** qnap
**CVSS Base Score:** 4.9
**Severity:** MEDIUM
**Published:** 2024-03-08T17:15:21.613000+00:00
**Last Modified:** 2025-12-05T21:49:39.607000+00:00
**Description:** A cross-site scripting (XSS) vulnerability has been reported to affect Network & Virtual Switch. If exploited, the vulnerability could allow authenticated administrators to inject malicious code via a network.  We have already fixed the vulnerability in the following versions: QuTScloud c5.1.5.2651 and later QTS 5.1.4.2596 build 20231128 and later QuTS hero h5.1.4.2596 build 20231128 and later ...

---

### CVE-2024-28859
**Vendor:** Swift
**CVSS Base Score:** 5.0
**Severity:** MEDIUM
**Published:** 2024-03-15T23:15:08.117000+00:00
**Last Modified:** 2025-12-05T17:59:08.813000+00:00
**Description:** Symfony1 is a community fork of symfony 1.4 with DIC, form enhancements, latest Swiftmailer, better performance, composer compatible and PHP 8 support. Symfony 1 has a gadget chain due to vulnerable Swift Mailer dependency that would enable an attacker to get remote code execution if a developer unserialize user input in his project. This vulnerability present no direct threat but is a vector that...

---

### CVE-2023-47222
**Vendor:** qnap
**CVSS Base Score:** 9.6
**Severity:** CRITICAL
**Published:** 2024-04-26T15:15:46.870000+00:00
**Last Modified:** 2025-12-05T21:26:21.367000+00:00
**Description:** An exposure of sensitive information vulnerability has been reported to affect Media Streaming add-on. If exploited, the vulnerability could allow users to compromise the security of the system via a network.  We have already fixed the vulnerability in the following version: Media Streaming add-on  500.1.1.5 ( 2024/01/22 ) and later ...

---

### CVE-2024-21905
**Vendor:** qnap
**CVSS Base Score:** 6.5
**Severity:** MEDIUM
**Published:** 2024-04-26T15:15:48.313000+00:00
**Last Modified:** 2025-12-05T21:31:00.247000+00:00
**Description:** An integer overflow or wraparound vulnerability has been reported to affect several QNAP operating system versions. If exploited, the vulnerability could allow users to compromise the security of the system via a network.  We have already fixed the vulnerability in the following versions: QTS 5.1.3.2578 build 20231110 and later QuTS hero h5.1.3.2578 build 20231110 and later QuTScloud c5.1.5.2651 a...

---

### CVE-2024-27124
**Vendor:** qnap
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2024-04-26T15:15:48.500000+00:00
**Last Modified:** 2025-12-05T21:28:13.027000+00:00
**Description:** An OS command injection vulnerability has been reported to affect several QNAP operating system versions. If exploited, the vulnerability could allow users to execute commands via a network.  We have already fixed the vulnerability in the following versions: QTS 5.1.3.2578 build 20231110 and later QTS 4.5.4.2627 build 20231225 and later QuTS hero h5.1.3.2578 build 20231110 and later QuTS hero h4.5...

---

### CVE-2025-22399
**Vendor:** Dell
**CVSS Base Score:** 7.9
**Severity:** HIGH
**Published:** 2025-02-11T17:15:34.453000+00:00
**Last Modified:** 2025-12-06T00:48:40.830000+00:00
**Description:** Dell UCC Edge, version 2.3.0, contains a Blind SSRF on Add Customer SFTP Server vulnerability. An unauthenticated attacker with local access could potentially exploit this vulnerability, leading to Server-side request forgery...

---

### CVE-2025-21103
**Vendor:** Dell
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-02-17T14:15:08.597000+00:00
**Last Modified:** 2025-12-06T00:39:24.330000+00:00
**Description:** Dell NetWorker Management Console, version(s) 19.11 through 19.11.0.3 & Versions prior to 19.10.0.7 contain(s) an improper neutralization of server-side vulnerability. An unauthenticated attacker with local access could potentially exploit this vulnerability and run arbitrary code on the server....

---

### CVE-2024-53696
**Vendor:** qnap
**CVSS Base Score:** 4.9
**Severity:** MEDIUM
**Published:** 2025-03-07T17:15:20.390000+00:00
**Last Modified:** 2025-12-06T00:34:08.557000+00:00
**Description:** A server-side request forgery (SSRF) vulnerability has been reported to affect QuLog Center. If exploited, the vulnerability could allow remote attackers who have gained administrator access to read application data.  We have already fixed the vulnerability in the following versions: QuLog Center 1.7.0.829 ( 2024/10/01 ) and later QuLog Center 1.8.0.888 ( 2024/10/15 ) and later QTS 4.5.4.2957 buil...

---

### CVE-2024-50406
**Vendor:** qnap
**CVSS Base Score:** 5.4
**Severity:** MEDIUM
**Published:** 2025-06-06T16:15:23.500000+00:00
**Last Modified:** 2025-12-05T21:10:30.703000+00:00
**Description:** A cross-site scripting (XSS) vulnerability has been reported to affect License Center. If exploited, the vulnerability could allow remote attackers who have gained user access to bypass security mechanisms or read application data.  We have already fixed the vulnerability in the following version: License Center 1.9.49 and later...

---

### CVE-2025-22483
**Vendor:** qnap
**CVSS Base Score:** 4.8
**Severity:** MEDIUM
**Published:** 2025-08-29T17:15:33.877000+00:00
**Last Modified:** 2025-12-05T21:09:44.810000+00:00
**Description:** A cross-site scripting (XSS) vulnerability has been reported to affect several QNAP operating system versions. If a remote attacker gains an administrator account, they can then exploit the vulnerability to bypass security mechanisms or read application data.  We have already fixed the vulnerability in the following versions: License Center 1.8.51 and later License Center 1.9.51 and later...

---

### CVE-2025-22166
**Vendor:** Jira
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-10-21T16:15:37.370000+00:00
**Last Modified:** 2025-12-05T19:22:44.947000+00:00
**Description:** This High severity DoS (Denial of Service) vulnerability was introduced in version 2.0 of Confluence Data Center.  This DoS (Denial of Service) vulnerability, with a CVSS Score of 8.3, allows an attacker to cause a resource to be unavailable for its intended users by temporarily or indefinitely disrupting services of a host connected to a network.  Atlassian recommends that Confluence Data Cen...

---

### CVE-2025-46608
**Vendor:** Dell
**CVSS Base Score:** 9.1
**Severity:** CRITICAL
**Published:** 2025-11-12T21:15:50.300000+00:00
**Last Modified:** 2025-12-05T20:39:41.723000+00:00
**Description:** Dell Data Lakehouse, versions prior to 1.6.0.0, contain(s) an Improper Access Control vulnerability. A high privileged attacker with remote access could potentially exploit this vulnerability, leading to Elevation of privileges. This vulnerability is considered Critical, as it may result in unauthorized access with elevated privileges, compromising system integrity and customer data. Dell recommen...

---

### CVE-2025-12893
**Vendor:** Jira
**CVSS Base Score:** 4.2
**Severity:** MEDIUM
**Published:** 2025-11-25T05:15:59.700000+00:00
**Last Modified:** 2025-12-05T20:26:41.497000+00:00
**Description:** Clients may successfully perform a TLS handshake with a MongoDB server despite presenting a client certificate not aligning with the documented Extended Key Usage (EKU) requirements. A certificate that specifies extendedKeyUsage but is missing extendedKeyUsage = clientAuth may still be successfully authenticated via the TLS handshake as a client. This issue is specific to MongoDB servers running o...

---

### CVE-2025-13507
**Vendor:** Jira
**CVSS Base Score:** 6.5
**Severity:** MEDIUM
**Published:** 2025-11-25T05:16:09.090000+00:00
**Last Modified:** 2025-12-05T20:23:31.947000+00:00
**Description:** Inconsistent object size validation in time series processing logic may result in later processing of oversized BSON documents leading to an assert failing and process termination.  This issue impacts MongoDB Server v7.0 versions prior to 7.0.26, v8.0 versions prior to 8.0.16 and MongoDB server v8.2 versions prior to 8.2.1....

---

### CVE-2024-48882
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T16:15:49.983000+00:00
**Last Modified:** 2025-12-05T21:10:23.050000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2024-48894
**Vendor:** Cisco
**CVSS Base Score:** 5.9
**Severity:** MEDIUM
**Published:** 2025-12-01T16:15:50.160000+00:00
**Last Modified:** 2025-12-05T21:10:30.213000+00:00
**Description:** A cleartext transmission vulnerability exists in the WEBVIEW-M functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted HTTP request can lead to a disclosure of sensitive information. An attacker can sniff network traffic to trigger this vulnerability....

---

### CVE-2024-49572
**Vendor:** Cisco
**CVSS Base Score:** 7.2
**Severity:** HIGH
**Published:** 2025-12-01T16:15:50.340000+00:00
**Last Modified:** 2025-12-05T21:10:36.057000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service and weaken credentials resulting in default documented credentials being applied to the device. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2024-53684
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T16:15:50.513000+00:00
**Last Modified:** 2025-12-05T21:10:42.877000+00:00
**Description:** A cross-site request forgery (csrf) vulnerability exists in the WEBVIEW-M functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted HTTP request can lead to unauthorized access. An attacker can stage a malicious webpage to trigger this vulnerability....

---

### CVE-2025-20085
**Vendor:** Cisco
**CVSS Base Score:** 7.2
**Severity:** HIGH
**Published:** 2025-12-01T16:15:51.960000+00:00
**Last Modified:** 2025-12-05T20:49:00.420000+00:00
**Description:** A denial of service vulnerability exists in the Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service and weaken credentials resulting in default documented credentials being applied to the device. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2025-23417
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T16:15:52.207000+00:00
**Last Modified:** 2025-12-05T20:49:08.017000+00:00
**Description:** A denial of service vulnerability exists in the Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2025-26858
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T16:15:52.387000+00:00
**Last Modified:** 2025-12-05T20:49:15.240000+00:00
**Description:** A buffer overflow vulnerability exists in the Modbus TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted set of network packets can lead to denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability....

---

### CVE-2025-54850
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T16:15:54.080000+00:00
**Last Modified:** 2025-12-05T20:20:10.270000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted series of network requests can lead to a denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability.An attacker can trigger this denial-of-service condition by sending a sequence of Modbus RTU ove...

---

### CVE-2025-54851
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T16:15:54.260000+00:00
**Last Modified:** 2025-12-05T20:47:17.533000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted series of network requests can lead to a denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability.An attacker can trigger this denial-of-service condition by sending a single Modbus TCP message ...

---

### CVE-2025-55221
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T16:15:54.443000+00:00
**Last Modified:** 2025-12-05T20:47:43.500000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP USB Function functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to a denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability.This vulnerability is specific to the malicious message sent via Modbus TCP over port 502....

---

### CVE-2025-55222
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T16:15:54.620000+00:00
**Last Modified:** 2025-12-05T20:48:02.067000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP USB Function functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to a denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability.This vulnerability is specific to the malicious message sent via Modbus RTU over TCP on port 503....

---

### CVE-2025-55182
**Vendor:** facebook
**CVSS Base Score:** 10.0
**Severity:** CRITICAL
**Published:** 2025-12-03T16:15:56.463000+00:00
**Last Modified:** 2025-12-06T02:00:02.510000+00:00
**Known Exploited (KEV):** Yes
**Description:** A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints....

---

### CVE-2025-13492
**Vendor:** HP
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-12-03T17:15:49.733000+00:00
**Last Modified:** 2025-12-05T23:51:25.677000+00:00
**Description:** A potential security vulnerability has been identified in HP Image Assistant for versions prior to 5.3.3. The vulnerability                could potentially allow a local attacker to escalate privileges via a race condition when installing packages....

---

### CVE-2025-20382
**Vendor:** Cisco
**CVSS Base Score:** 3.5
**Severity:** LOW
**Published:** 2025-12-03T17:15:50.380000+00:00
**Last Modified:** 2025-12-05T18:33:45.600000+00:00
**Description:** In Splunk Enterprise versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, and Splunk Cloud Platform versions below 10.1.2507.10, 10.0.2503.8, and 9.3.2411.120, a low-privileged user that does not hold the "admin" or "power" Splunk roles could create a views dashboard with a custom background using the `data:image/png;base64` protocol that could potentially lead to an unvalidated redirect. This behavio...

---

### CVE-2025-20383
**Vendor:** Cisco
**CVSS Base Score:** 4.3
**Severity:** MEDIUM
**Published:** 2025-12-03T17:15:50.567000+00:00
**Last Modified:** 2025-12-05T18:30:13.090000+00:00
**Description:** In Splunk Enterprise versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, and below 3.9.10, 3.8.58, and 3.7.28 of Splunk Secure Gateway app in Splunk Cloud Platform, a low-privileged user that does not hold the "admin" or "power" Splunk roles and subscribes to mobile push notifications could receive notifications that disclose the title and description of the report or alert even if they do not have a...

---

### CVE-2025-20384
**Vendor:** Cisco
**CVSS Base Score:** 5.3
**Severity:** MEDIUM
**Published:** 2025-12-03T17:15:50.740000+00:00
**Last Modified:** 2025-12-05T18:14:07.767000+00:00
**Description:** In Splunk Enterprise versions below 10.0.1, 9.4.6, 9.3.8, and 9.2.10, and Splunk Cloud Platform versions below 10.1.2507.4, 10.0.2503.6, and 9.3.2411.117.125, an unauthenticated attacker can inject American National Standards Institute (ANSI) escape codes into Splunk log files due to improper validation at the /en-US/static/ web endpoint. This may allow them to poison, forge, or obfuscate sensitiv...

---

### CVE-2025-20385
**Vendor:** Cisco
**CVSS Base Score:** 2.4
**Severity:** LOW
**Published:** 2025-12-03T17:15:50.910000+00:00
**Last Modified:** 2025-12-05T18:13:10.887000+00:00
**Description:** In Splunk Enterprise versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, and Splunk Cloud Platform versions below 10.1.2507.6, 10.0.2503.7, and 9.3.2411.117, a user who holds a role with a high privilege capability `admin_all_objects` could craft a malicious payload through the href attribute of an anchor tag within a collection in the navigation bar, which could result in execution of unauthorized J...

---

### CVE-2025-20386
**Vendor:** Cisco
**CVSS Base Score:** 8.0
**Severity:** HIGH
**Published:** 2025-12-03T17:15:51.080000+00:00
**Last Modified:** 2025-12-05T17:51:41.637000+00:00
**Description:** In Splunk Enterprise for Windows versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, a new installation of or an upgrade to an affected version can result in incorrect permissions assignment in the Splunk Enterprise for Windows Installation directory. This lets non-administrator users on the machine access the directory and all its contents....

---

### CVE-2025-20387
**Vendor:** Cisco
**CVSS Base Score:** 8.0
**Severity:** HIGH
**Published:** 2025-12-03T17:15:51.257000+00:00
**Last Modified:** 2025-12-05T17:35:09.560000+00:00
**Description:** In Splunk Universal Forwarder for Windows versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, a new installation of or an upgrade to an affected version can result in incorrect permissions assignment in the Universal Forwarder for Windows Installation directory. This lets non-administrator users on the machine access the directory and all its contents....

---

### CVE-2025-20388
**Vendor:** Cisco
**CVSS Base Score:** 2.7
**Severity:** LOW
**Published:** 2025-12-03T17:15:51.427000+00:00
**Last Modified:** 2025-12-05T17:11:26.647000+00:00
**Description:** In Splunk Enterprise versions below 10.0.1, 9.4.6, 9.3.8, and 9.2.10, and Splunk Cloud Platform versions below 10.1.2507.4, 10.0.2503.7, and 9.3.2411.116, a user who holds a role that contains the high privilege capability `change_authentication` could enumerate internal IP addresses and network ports when adding new search peers to a Splunk search head in a distributed environment....

---

### CVE-2025-20389
**Vendor:** Cisco
**CVSS Base Score:** 4.3
**Severity:** MEDIUM
**Published:** 2025-12-03T17:15:51.610000+00:00
**Last Modified:** 2025-12-05T17:05:57.880000+00:00
**Description:** In Splunk Enterprise versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, and versions below 3.9.10, 3.8.58 and 3.7.28 of the Splunk Secure Gateway app on Splunk Cloud Platform, a low-privileged user that does not hold the "admin" or "power" Splunk roles could craft a malicious payload through the `label` column field after adding a new device in the Splunk Secure Gateway app. This could potentially l...

---

### CVE-2025-40261
**Vendor:** Dell
**CVSS Base Score:** N/A
**Severity:** N/A
**Published:** 2025-12-04T16:16:20.053000+00:00
**Last Modified:** 2025-12-06T22:15:53.647000+00:00
**Description:** In the Linux kernel, the following vulnerability has been resolved:  nvme: nvme-fc: Ensure ->ioerr_work is cancelled in nvme_fc_delete_ctrl()  nvme_fc_delete_assocation() waits for pending I/O to complete before returning, and an error can cause ->ioerr_work to be queued after cancel_work_sync() had been called.  Move the call to cancel_work_sync() to be after nvme_fc_delete_association() to ensur...

---

### CVE-2025-66576
**Vendor:** Microsoft
**CVSS Base Score:** N/A
**Severity:** N/A
**Published:** 2025-12-04T21:16:10.600000+00:00
**Last Modified:** 2025-12-05T18:16:00.110000+00:00
**Description:** Remote Keyboard Desktop 1.0.1 enables remote attackers to execute system commands via the rundll32.exe exported function export, allowing unauthenticated code execution....

---

### CVE-2025-9491
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-08-26T17:15:41.337000+00:00
**Last Modified:** 2025-11-05T21:15:36.513000+00:00
**Source:** [https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html](https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html)
**Description:** Microsoft Windows LNK File UI Misrepresentation Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Microsoft Windows. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.  The specific flaw exists within the handling of .LNK files. Craft...

---

### CVE-2025-20341
**Vendor:** Cisco
**CVSS Base Score:** 8.8
**Severity:** HIGH
**Published:** 2025-11-13T17:15:45.400000+00:00
**Last Modified:** 2025-11-14T16:42:03.187000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0365](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0365)
**Description:** A vulnerability in Cisco Catalyst Center Virtual Appliance could allow an authenticated, remote attacker to elevate privileges to Administrator on an affected system.  This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted HTTP request to an affected system. A successful exploit could allow the attacker to...

---

### CVE-2025-62222
**Vendor:** Microsoft
**CVSS Base Score:** 8.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:49.887000+00:00
**Last Modified:** 2025-11-14T15:47:58.830000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0362](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0362)
**Description:** Improper neutralization of special elements used in a command ('command injection') in Visual Studio Code CoPilot Chat Extension allows an unauthorized attacker to execute code over a network....

---

### CVE-2025-62453
**Vendor:** Microsoft
**CVSS Base Score:** 5.0
**Severity:** MEDIUM
**Published:** 2025-11-11T18:15:50.423000+00:00
**Last Modified:** 2025-11-14T15:30:40.577000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0362](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0362)
**Description:** Improper validation of generative ai output in GitHub Copilot and Visual Studio Code allows an authorized attacker to bypass a security feature locally....

---

### CVE-2025-62204
**Vendor:** Microsoft
**CVSS Base Score:** 8.0
**Severity:** HIGH
**Published:** 2025-11-11T18:15:45.513000+00:00
**Last Modified:** 2025-11-17T18:01:37.127000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359)
**Description:** Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network....

---

### CVE-2025-60724
**Vendor:** Microsoft
**CVSS Base Score:** 9.8
**Severity:** CRITICAL
**Published:** 2025-11-11T18:15:41.060000+00:00
**Last Modified:** 2025-11-17T17:40:24.140000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359)
**Description:** Heap-based buffer overflow in Microsoft Graphics Component allows an unauthorized attacker to execute code over a network....

---

### CVE-2025-60722
**Vendor:** Microsoft
**CVSS Base Score:** 6.5
**Severity:** MEDIUM
**Published:** 2025-11-11T18:15:40.733000+00:00
**Last Modified:** 2025-11-17T17:40:29.363000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359)
**Description:** Improper limitation of a pathname to a restricted directory ('path traversal') in OneDrive for Android allows an authorized attacker to elevate privileges over a network....

---

### CVE-2025-62199
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:43.013000+00:00
**Last Modified:** 2025-11-19T15:15:49.570000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359)
**Description:** Use after free in Microsoft Office allows an unauthorized attacker to execute code locally....

---

### CVE-2025-60727
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:41.397000+00:00
**Last Modified:** 2025-11-17T18:03:46.800000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359)
**Description:** Out-of-bounds read in Microsoft Office Excel allows an unauthorized attacker to execute code locally....

---

### CVE-2025-62200
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:43.237000+00:00
**Last Modified:** 2025-11-17T18:01:59.723000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0359)
**Description:** Untrusted pointer dereference in Microsoft Office Excel allows an unauthorized attacker to execute code locally....

---

### CVE-2025-59506
**Vendor:** Microsoft
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-11-11T18:15:36.230000+00:00
**Last Modified:** 2025-11-17T18:01:15.073000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Concurrent execution using shared resource with improper synchronization ('race condition') in Windows DirectX allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-60716
**Vendor:** Microsoft
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-11-11T18:15:39.740000+00:00
**Last Modified:** 2025-11-17T17:42:54.597000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Use after free in Windows DirectX allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-59513
**Vendor:** Microsoft
**CVSS Base Score:** 5.5
**Severity:** MEDIUM
**Published:** 2025-11-11T18:15:37.397000+00:00
**Last Modified:** 2025-11-17T17:47:32.230000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Out-of-bounds read in Windows Bluetooth RFCOM Protocol Driver allows an authorized attacker to disclose information locally....

---

### CVE-2025-62209
**Vendor:** Microsoft
**CVSS Base Score:** 5.5
**Severity:** MEDIUM
**Published:** 2025-11-11T18:15:48.100000+00:00
**Last Modified:** 2025-11-17T17:40:05.017000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Insertion of sensitive information into log file in Windows License Manager allows an authorized attacker to disclose information locally....

---

### CVE-2025-60703
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:37.890000+00:00
**Last Modified:** 2025-11-17T17:47:19.307000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Untrusted pointer dereference in Windows Remote Desktop allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-60720
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:40.400000+00:00
**Last Modified:** 2025-11-17T17:42:39.480000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Buffer over-read in Windows TDX.sys allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-59511
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:37.067000+00:00
**Last Modified:** 2025-11-17T17:47:38.977000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** External control of file name or path in Windows WLAN Service allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-60719
**Vendor:** Microsoft
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-11-11T18:15:40.233000+00:00
**Last Modified:** 2025-11-17T17:42:43.480000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Untrusted pointer dereference in Windows Ancillary Function Driver for WinSock allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-60709
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T18:15:38.903000+00:00
**Last Modified:** 2025-11-17T17:43:21.477000+00:00
**Source:** [http://www.zerodayinitiative.com/advisories/ZDI-25-1001/](http://www.zerodayinitiative.com/advisories/ZDI-25-1001/)
**Description:** Out-of-bounds read in Windows Common Log File System Driver allows an authorized attacker to elevate privileges locally....

---

### CVE-2024-13087
**Vendor:** qnap
**CVSS Base Score:** 6.7
**Severity:** MEDIUM
**Published:** 2025-06-06T16:15:22.573000+00:00
**Last Modified:** 2025-09-24T20:32:32.280000+00:00
**Source:** [http://www.zerodayinitiative.com/advisories/ZDI-25-871/](http://www.zerodayinitiative.com/advisories/ZDI-25-871/)
**Description:** A command injection vulnerability has been reported to affect QHora. If an attacker gains local network access who have also gained an administrator account, they can then exploit the vulnerability to execute arbitrary commands.  We have already fixed the vulnerability in the following version: QuRouter 2.4.6.028 and later...

---
