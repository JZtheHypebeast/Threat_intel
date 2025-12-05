# Structured CVE Intelligence Report

**Generated:** 2025-12-03 19:17 UTC  

**Window:** Last 48 hours

---

## Critical CVEs (CVSS ≥ 8.5)

### CVE-2025-12744
**Vendor:** docker
**CVSS Base Score:** 8.8
**Severity:** HIGH
**Published:** 2025-12-03T13:15:46.390000+00:00
**Description:** A flaw was found in the ABRT daemon’s handling of user-supplied mount information.ABRT copies up to 12 characters from an untrusted input and places them directly into a shell command (docker inspect %s) without proper validation. An unprivileged local user can craft a payload that injects shell metacharacters, causing the root-running ABRT process to execute attacker-controlled commands and ultim...

---

### CVE-2025-55182
**Vendor:** facebook
**CVSS Base Score:** 10.0
**Severity:** CRITICAL
**Published:** 2025-12-03T20:15:56.463000+00:00
**Description:** A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints....

---

## Interesting CVEs (CVSS 6.5–8.5)

### CVE-2025-58113
**Vendor:** Cisco
**CVSS Base Score:** 6.5
**Severity:** MEDIUM
**Published:** 2025-12-02T20:15:55.040000+00:00
**Description:** An out-of-bounds read vulnerability exists in the EMF functionality of PDF-XChange Co. Ltd PDF-XChange Editor 10.7.3.401.  By using a specially crafted EMF file, an attacker could exploit this vulnerability to perform an out-of-bounds read, potentially leading to the disclosure of sensitive information....

---

### CVE-2025-62575
**Vendor:** Microsoft
**CVSS Base Score:** 8.3
**Severity:** HIGH
**Published:** 2025-12-03T01:15:52.133000+00:00
**Description:** NMIS/BioDose V22.02 and previous versions rely on a Microsoft SQL Server database. The SQL user account 'nmdbuser' and other created accounts by default have the sysadmin role. This can lead to remote code execution through the use of certain built-in stored procedures....

---

### CVE-2025-64298
**Vendor:** Microsoft
**CVSS Base Score:** 8.4
**Severity:** HIGH
**Published:** 2025-12-03T01:15:52.333000+00:00
**Description:** NMIS/BioDose V22.02 and previous version installations where the embedded Microsoft SQLServer Express is used are exposed in the Windows share accessed by clients in networked installs. By default, this directory has insecure directory paths that allow access to the SQL Server database and configuration files, which can contain sensitive data....

---

### CVE-2025-20386
**Vendor:** Cisco
**CVSS Base Score:** 8.0
**Severity:** HIGH
**Published:** 2025-12-03T21:15:51.080000+00:00
**Description:** In Splunk Enterprise for Windows versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, a new installation of or an upgrade to an affected version can result in incorrect permissions assignment in the Splunk Enterprise for Windows Installation directory. This lets non-administrator users on the machine access the directory and all its contents....

---

### CVE-2025-20387
**Vendor:** Cisco
**CVSS Base Score:** 8.0
**Severity:** HIGH
**Published:** 2025-12-03T21:15:51.257000+00:00
**Description:** In Splunk Universal Forwarder for Windows versions below 10.0.2, 9.4.6, 9.3.8, and 9.2.10, a new installation of or an upgrade to an affected version can result in incorrect permissions assignment in the Universal Forwarder for Windows Installation directory. This lets non-administrator users on the machine access the directory and all its contents....

---

## Recently Modified CVEs (Last 48h)

### CVE-2018-19591
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2018-12-04T20:29:00.480000+00:00
**Last Modified:** 2025-12-03T23:15:47.627000+00:00
**Description:** In the GNU C Library (aka glibc or libc6) through 2.28, attempting to resolve a crafted hostname via getaddrinfo() leads to the allocation of a socket descriptor that is not closed. This is related to the if_nametoindex() function....

---

### CVE-2019-15166
**Vendor:** NetApp
**CVSS Base Score:** 1.6
**Severity:** LOW
**Published:** 2019-10-03T21:15:11.050000+00:00
**Last Modified:** 2025-12-03T23:15:49.470000+00:00
**Description:** lmp_print_data_link_subobjs() in print-lmp.c in tcpdump before 4.9.3 lacks certain bounds checks....

---

### CVE-2019-19956
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2019-12-24T20:15:11.450000+00:00
**Last Modified:** 2025-12-03T23:15:50.247000+00:00
**Description:** xmlParseBalancedChunkMemoryRecover in parser.c in libxml2 before 2.9.10 has a memory leak related to newDoc->oldNs....

---

### CVE-2020-7595
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2020-01-22T03:15:13.867000+00:00
**Last Modified:** 2025-12-03T20:15:54.123000+00:00
**Description:** xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file situation....

---

### CVE-2020-8597
**Vendor:** NetApp
**CVSS Base Score:** 9.8
**Severity:** CRITICAL
**Published:** 2020-02-04T03:15:11.387000+00:00
**Last Modified:** 2025-12-03T20:15:54.430000+00:00
**Description:** eap.c in pppd in ppp 2.4.2 through 2.4.8 has an rhostname buffer overflow in the eap_request and eap_response functions....

---

### CVE-2020-15861
**Vendor:** NetApp
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2020-08-20T05:17:13.837000+00:00
**Last Modified:** 2025-12-03T23:15:51.413000+00:00
**Description:** Net-SNMP through 5.7.3 allows Escalation of Privileges because of UNIX symbolic link (symlink) following....

---

### CVE-2020-28196
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2020-11-06T12:15:13.860000+00:00
**Last Modified:** 2025-12-03T23:15:52.130000+00:00
**Description:** MIT Kerberos 5 (aka krb5) before 1.17.2 and 1.18.x before 1.18.3 allows unbounded recursion via an ASN.1-encoded Kerberos message because the lib/krb5/asn.1/asn1_encode.c support for BER indefinite lengths lacks a recursion limit....

---

### CVE-2021-20232
**Vendor:** NetApp
**CVSS Base Score:** 9.8
**Severity:** CRITICAL
**Published:** 2021-03-12T23:15:13.130000+00:00
**Last Modified:** 2025-12-03T19:15:48.943000+00:00
**Description:** A flaw was found in gnutls. A use after free issue in client_send_params in lib/ext/pre_shared_key.c may lead to memory corruption and other potential consequences....

---

### CVE-2021-20197
**Vendor:** NetApp
**CVSS Base Score:** 6.3
**Severity:** MEDIUM
**Published:** 2021-03-26T21:15:12.920000+00:00
**Last Modified:** 2025-12-03T19:15:46.777000+00:00
**Description:** There is an open race window when writing output in the following utilities in GNU binutils version 2.35 and earlier:ar, objcopy, strip, ranlib. When these utilities are run as a privileged user (presumably as part of a script updating binaries across different users), an unprivileged user can trick these utilities into getting ownership of arbitrary files through a symlink....

---

### CVE-2021-3517
**Vendor:** NetApp
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2021-05-19T18:15:07.553000+00:00
**Last Modified:** 2025-12-03T02:16:07.097000+00:00
**Description:** There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker who is able to supply a crafted file to be processed by an application linked with the affected functionality of libxml2 could trigger an out-of-bounds read. The most likely impact of this flaw is to application availability, with some potential impact to confidentiality and integrity if an a...

---

### CVE-2021-3999
**Vendor:** NetApp
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2022-08-24T20:15:09.077000+00:00
**Last Modified:** 2025-12-03T01:15:49.210000+00:00
**Description:** A flaw was found in glibc. An off-by-one buffer overflow and underflow in getcwd() may lead to memory corruption when the size of the buffer is exactly 1. A local attacker who can control the input buffer and size passed to getcwd() in a setuid program could use this flaw to potentially execute arbitrary code and escalate their privileges on the system....

---

### CVE-2023-38039
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2023-09-15T08:15:10.127000+00:00
**Last Modified:** 2025-12-03T00:15:46.680000+00:00
**Description:** When curl retrieves an HTTP response, it stores the incoming headers so that they can be accessed later via the libcurl headers API.  However, curl did not have a limit in how many or how large headers it would accept in a response, allowing a malicious server to stream an endless series of headers and eventually cause curl to run out of heap memory....

---

### CVE-2023-3341
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2023-09-20T17:15:11.770000+00:00
**Last Modified:** 2025-12-03T01:15:51.420000+00:00
**Description:** The code that processes control channel messages sent to `named` calls certain functions recursively during packet parsing. Recursion depth is only limited by the maximum accepted packet size; depending on the environment, this may cause the packet-parsing code to run out of available stack memory, causing `named` to terminate unexpectedly. Since each incoming control channel message is fully pars...

---

### CVE-2023-5363
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2023-10-25T22:17:43.613000+00:00
**Last Modified:** 2025-12-03T00:15:48.537000+00:00
**Description:** Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths.  This can lead to potential truncation or overruns during the initialisation of some symmetric ciphers.  Impact summary: A truncation in the IV can result in non-uniqueness, which could result in loss of confidentiality for some cipher modes.  When calling EVP_EncryptInit_ex2(), EVP_DecryptIni...

---

### CVE-2023-5678
**Vendor:** NetApp
**CVSS Base Score:** 5.3
**Severity:** MEDIUM
**Published:** 2023-11-06T20:15:42.670000+00:00
**Last Modified:** 2025-12-03T00:15:49.157000+00:00
**Description:** Issue summary: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow.  Impact summary: Applications that use the functions DH_generate_key() to generate an X9.42 DH key may experience long delays.  Likewise, applications that use DH_check_pub_key(), DH_check_pub_key_ex() or EVP_PKEY_public_check() to check an X9.42 DH key or X9.42 DH pa...

---

### CVE-2023-46219
**Vendor:** NetApp
**CVSS Base Score:** 5.3
**Severity:** MEDIUM
**Published:** 2023-12-12T06:15:06.990000+00:00
**Last Modified:** 2025-12-03T00:15:48.023000+00:00
**Description:** When saving HSTS data to an excessively long file name, curl could end up removing all contents, making subsequent requests using that file unaware of the HSTS status they should otherwise use....

---

### CVE-2024-34069
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2024-05-06T19:15:23.990000+00:00
**Last Modified:** 2025-12-03T19:32:11.177000+00:00
**Description:** Werkzeug is a comprehensive WSGI web application library. The debugger in affected versions of Werkzeug can allow an attacker to execute code on a developer's machine under some circumstances. This requires the attacker to get the developer to interact with a domain and subdomain they control, and enter the debugger PIN, but if they are successful it allows access to the debugger even if it is onl...

---

### CVE-2024-49766
**Vendor:** NetApp
**CVSS Base Score:** 5.3
**Severity:** MEDIUM
**Published:** 2024-10-26T00:15:04.410000+00:00
**Last Modified:** 2025-12-03T19:29:37.613000+00:00
**Description:** Werkzeug is a Web Server Gateway Interface web application library. On Python < 3.11 on Windows, os.path.isabs() does not catch UNC paths like //server/share. Werkzeug's safe_join() relies on this check, and so can produce a path that is not safe, potentially allowing unintended access to data. Applications using Python >= 3.11, or not using Windows, are not vulnerable. Werkzeug version 3.0.6 cont...

---

### CVE-2024-52541
**Vendor:** Dell
**CVSS Base Score:** 8.2
**Severity:** HIGH
**Published:** 2025-02-19T21:15:14.633000+00:00
**Last Modified:** 2025-12-01T23:22:48.750000+00:00
**Description:** Dell Client Platform BIOS contains a Weak Authentication vulnerability. A high privileged attacker with local access could potentially exploit this vulnerability, leading to Elevation of Privileges....

---

### CVE-2024-8176
**Vendor:** NetApp
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-03-14T13:15:14.157000+00:00
**Last Modified:** 2025-12-02T19:15:48.640000+00:00
**Description:** A stack overflow vulnerability exists in the libexpat library due to the way it handles recursive entity expansion in XML documents. When parsing an XML document with deeply nested entity references, libexpat can be forced to recurse indefinitely, exhausting the stack space and causing a crash. This issue could lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depen...

---

### CVE-2025-59230
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-10-14T21:16:04.173000+00:00
**Last Modified:** 2025-12-03T17:47:09.720000+00:00
**Known Exploited (KEV):** Yes
**Description:** Improper access control in Windows Remote Access Connection Manager allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-53814
**Vendor:** Cisco
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-10-28T18:15:58.973000+00:00
**Last Modified:** 2025-12-02T20:04:34.467000+00:00
**Description:** A use-after-free vulnerability exists in the XML parser functionality of GCC Productions Inc. Fade In 4.2.0. A specially crafted .xml file can lead to heap-based memory corruption. An attacker can provide a malicious file to trigger this vulnerability....

---

### CVE-2025-53855
**Vendor:** Cisco
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-10-28T18:15:59.153000+00:00
**Last Modified:** 2025-12-02T20:04:31.883000+00:00
**Description:** An out-of-bounds write vulnerability exists in the XML parser functionality of GCC Productions Inc. Fade In 4.2.0. A specially crafted .fadein file can lead to an out-of-bounds write. An attacker can provide a malicious file to trigger this vulnerability....

---

### CVE-2025-48982
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-10-31T04:15:36.437000+00:00
**Last Modified:** 2025-12-02T01:15:50.380000+00:00
**Description:** This vulnerability in Veeam Agent for Microsoft Windows allows for Local Privilege Escalation if a system administrator is tricked into restoring a malicious file....

---

### CVE-2025-48983
**Vendor:** veeam
**CVSS Base Score:** 9.9
**Severity:** CRITICAL
**Published:** 2025-10-31T04:15:36.553000+00:00
**Last Modified:** 2025-12-02T01:15:50.527000+00:00
**Description:** A vulnerability in the Mount service of Veeam Backup & Replication, which allows for remote code execution (RCE) on the Backup infrastructure hosts by an authenticated domain user....

---

### CVE-2025-52881
**Vendor:** docker
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-11-07T01:15:42.817000+00:00
**Last Modified:** 2025-12-03T22:37:17.917000+00:00
**Description:** runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7, 1.3.2 and 1.4.0-rc.2, an attacker can trick runc into misdirecting writes to /proc to other procfs files through the use of a racing container with shared mounts (we have also verified this attack is possible to exploit using a standard Dockerfile with docker buildx build as that also perm...

---

### CVE-2025-12653
**Vendor:** JOIN
**CVSS Base Score:** 6.5
**Severity:** MEDIUM
**Published:** 2025-11-27T00:15:49.023000+00:00
**Last Modified:** 2025-12-03T00:36:11.933000+00:00
**Description:** GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.3 before 18.4.5, 18.5 before 18.5.3, and 18.6 before 18.6.1 that under specific conditions could have allowed an unauthenticated user to join arbitrary organizations by changing headers on some requests....

---

### CVE-2024-45370
**Vendor:** Cisco
**CVSS Base Score:** 7.3
**Severity:** HIGH
**Published:** 2025-12-01T20:15:49.757000+00:00
**Last Modified:** 2025-12-02T21:16:43.890000+00:00
**Description:** An authentication bypass vulnerability exists in the User profile management functionality of Socomec Easy Config System 2.6.1.0. A specially crafted database record can lead to unauthorized access. An attacker can modify a local database to trigger this vulnerability....

---

### CVE-2024-48882
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T20:15:49.983000+00:00
**Last Modified:** 2025-12-02T21:16:43.890000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2024-48894
**Vendor:** Cisco
**CVSS Base Score:** 5.9
**Severity:** MEDIUM
**Published:** 2025-12-01T20:15:50.160000+00:00
**Last Modified:** 2025-12-02T21:16:43.890000+00:00
**Description:** A cleartext transmission vulnerability exists in the WEBVIEW-M functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted HTTP request can lead to a disclosure of sensitive information. An attacker can sniff network traffic to trigger this vulnerability....

---

### CVE-2024-49572
**Vendor:** Cisco
**CVSS Base Score:** 7.2
**Severity:** HIGH
**Published:** 2025-12-01T20:15:50.340000+00:00
**Last Modified:** 2025-12-02T21:16:43.890000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service and weaken credentials resulting in default documented credentials being applied to the device. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2024-53684
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T20:15:50.513000+00:00
**Last Modified:** 2025-12-02T21:16:43.890000+00:00
**Description:** A cross-site request forgery (csrf) vulnerability exists in the WEBVIEW-M functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted HTTP request can lead to unauthorized access. An attacker can stage a malicious webpage to trigger this vulnerability....

---

### CVE-2025-20085
**Vendor:** Cisco
**CVSS Base Score:** 7.2
**Severity:** HIGH
**Published:** 2025-12-01T20:15:51.960000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service and weaken credentials resulting in default documented credentials being applied to the device. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2025-23417
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T20:15:52.207000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability....

---

### CVE-2025-26858
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T20:15:52.387000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A buffer overflow vulnerability exists in the Modbus TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted set of network packets can lead to denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability....

---

### CVE-2025-54848
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T20:15:53.723000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted series of network requests can lead to a denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability.An attacker can trigger this denial-of-service condition by sending a sequence of Modbus TCP mes...

---

### CVE-2025-54849
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T20:15:53.900000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted series of network requests can lead to a denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability.An attacker can trigger this denial-of-service condition by sending a single Modbus TCP message ...

---

### CVE-2025-54850
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T20:15:54.080000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted series of network requests can lead to a denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability.An attacker can trigger this denial-of-service condition by sending a sequence of Modbus RTU ove...

---

### CVE-2025-54851
**Vendor:** Cisco
**CVSS Base Score:** 7.5
**Severity:** HIGH
**Published:** 2025-12-01T20:15:54.260000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted series of network requests can lead to a denial of service. An attacker can send a sequence of unauthenticated packets to trigger this vulnerability.An attacker can trigger this denial-of-service condition by sending a single Modbus TCP message ...

---

### CVE-2025-55221
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T20:15:54.443000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP USB Function functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to a denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability.This vulnerability is specific to the malicious message sent via Modbus TCP over port 502....

---

### CVE-2025-55222
**Vendor:** Cisco
**CVSS Base Score:** 8.6
**Severity:** HIGH
**Published:** 2025-12-01T20:15:54.620000+00:00
**Last Modified:** 2025-12-02T21:16:29.163000+00:00
**Description:** A denial of service vulnerability exists in the Modbus TCP and Modbus RTU over TCP USB Function functionality of Socomec DIRIS Digiware M-70 1.6.9. A specially crafted network packet can lead to a denial of service. An attacker can send an unauthenticated packet to trigger this vulnerability.This vulnerability is specific to the malicious message sent via Modbus RTU over TCP on port 503....

---

### CVE-2025-9491
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-08-26T21:15:41.337000+00:00
**Last Modified:** 2025-11-06T01:15:36.513000+00:00
**Source:** [https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html](https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html)
**Description:** Microsoft Windows LNK File UI Misrepresentation Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Microsoft Windows. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.  The specific flaw exists within the handling of .LNK files. Craft...

---

### CVE-2025-59287
**Vendor:** Microsoft
**CVSS Base Score:** 9.8
**Severity:** CRITICAL
**Published:** 2025-10-14T21:16:11.670000+00:00
**Last Modified:** 2025-11-12T18:33:19.727000+00:00
**Known Exploited (KEV):** Yes
**Source:** [https://thehackernews.com/2025/11/shadowpad-malware-actively-exploits.html](https://thehackernews.com/2025/11/shadowpad-malware-actively-exploits.html)
**Description:** Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network....

---

### CVE-2025-64446
**Vendor:** Fortinet
**CVSS Base Score:** 9.8
**Severity:** CRITICAL
**Published:** 2025-11-14T20:15:58.567000+00:00
**Last Modified:** 2025-11-21T22:27:33.730000+00:00
**Known Exploited (KEV):** Yes
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0366](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0366)
**Description:** A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests....

---

### CVE-2025-20349
**Vendor:** Cisco
**CVSS Base Score:** 6.3
**Severity:** MEDIUM
**Published:** 2025-11-13T21:15:45.817000+00:00
**Last Modified:** 2025-11-19T21:07:43.197000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0365](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0365)
**Description:** A vulnerability in the REST API of Cisco Catalyst Center could allow an authenticated, remote attacker to execute arbitrary commands in a restricted container as the root user.  This vulnerability is due to insufficient validation of user-supplied input in REST API request parameters. An attacker could exploit this vulnerability by sending a crafted API request to an affected device. A successfu...

---

### CVE-2025-62222
**Vendor:** Microsoft
**CVSS Base Score:** 8.8
**Severity:** HIGH
**Published:** 2025-11-11T22:15:49.887000+00:00
**Last Modified:** 2025-11-14T19:47:58.830000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0362](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0362)
**Description:** Improper neutralization of special elements used in a command ('command injection') in Visual Studio Code CoPilot Chat Extension allows an unauthorized attacker to execute code over a network....

---

### CVE-2025-59512
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T22:15:37.230000+00:00
**Last Modified:** 2025-11-20T23:16:20.927000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Improper access control in Customer Experience Improvement Program (CEIP) allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-62209
**Vendor:** Microsoft
**CVSS Base Score:** 5.5
**Severity:** MEDIUM
**Published:** 2025-11-11T22:15:48.100000+00:00
**Last Modified:** 2025-11-17T21:40:05.017000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Insertion of sensitive information into log file in Windows License Manager allows an authorized attacker to disclose information locally....

---

### CVE-2025-60713
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T22:15:39.233000+00:00
**Last Modified:** 2025-11-17T21:43:10.020000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Untrusted pointer dereference in Windows Routing and Remote Access Service (RRAS) allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-59514
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T22:15:37.560000+00:00
**Last Modified:** 2025-11-17T21:47:29.150000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Improper privilege management in Microsoft Streaming Service allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-60719
**Vendor:** Microsoft
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-11-11T22:15:40.233000+00:00
**Last Modified:** 2025-11-17T21:42:43.480000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Untrusted pointer dereference in Windows Ancillary Function Driver for WinSock allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-60709
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-11-11T22:15:38.903000+00:00
**Last Modified:** 2025-11-17T21:43:21.477000+00:00
**Source:** [https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358](https://advisories.ncsc.nl/advisory?id=NCSC-2025-0358)
**Description:** Out-of-bounds read in Windows Common Log File System Driver allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-58034
**Vendor:** Fortinet
**CVSS Base Score:** 7.2
**Severity:** HIGH
**Published:** 2025-11-18T21:16:05.057000+00:00
**Last Modified:** 2025-11-21T22:27:43.280000+00:00
**Known Exploited (KEV):** Yes
**Source:** [http://www.zerodayinitiative.com/advisories/ZDI-25-1014/](http://www.zerodayinitiative.com/advisories/ZDI-25-1014/)
**Description:** An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability [CWE-78] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4.0 through 7.4.10, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an authenticated attacker to execute unauthorized code on the underlying system via crafted HTT...

---

### CVE-2025-53132
**Vendor:** Microsoft
**CVSS Base Score:** 7.8
**Severity:** HIGH
**Published:** 2025-08-12T22:15:36.890000+00:00
**Last Modified:** 2025-10-15T21:15:53.557000+00:00
**Source:** [http://www.zerodayinitiative.com/advisories/ZDI-25-845/](http://www.zerodayinitiative.com/advisories/ZDI-25-845/)
**Description:** Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Win32K - GRFX allows an authorized attacker to elevate privileges locally....

---

### CVE-2025-53788
**Vendor:** Microsoft
**CVSS Base Score:** 7.0
**Severity:** HIGH
**Published:** 2025-08-12T22:15:47.047000+00:00
**Last Modified:** 2025-08-18T19:23:56.480000+00:00
**Source:** [http://www.zerodayinitiative.com/advisories/ZDI-25-844/](http://www.zerodayinitiative.com/advisories/ZDI-25-844/)
**Description:** Time-of-check time-of-use (toctou) race condition in Windows Subsystem for Linux allows an authorized attacker to elevate privileges locally....

---
