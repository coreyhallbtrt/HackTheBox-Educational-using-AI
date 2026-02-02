# HackTheBox Educational Writeups (using AI)

This repository will be a collection of HackTheBox machine writeups on hacking with a A.I assistant!!! I used Claude Opus 4.5. These writeups focus on teaching and not just showing what commands were run, but explaining why each step matters and how defenders can protect against these techniques. I believe that A.I can be used as a great teacher/educator if used in a educational way!

## Purpose

This repository is a learning resource for anyone interested in cybersecurity.

## The AI Behind This

These machines were hacked using **Claude Opus 4.5** through [Claude Code](https://claude.ai/claude-code), Anthropic's CLI tool. Claude Opus 4.5 assisted with every phase - from reconnaissance and vulnerability research to exploitation and privilege escalation. The AI helped identify attack vectors, explain vulnerabilities, suggest next steps when stuck, and document everything in an educational format.

## AI as a Hacking Partner

This project shows how AI can work as a collaborative partner in penetration testing. AI adds to it:

- **Research** - Quickly finding relevant CVEs, techniques, and patterns
- **Explanations** - Breaking down complex vulnerabilities into clear concepts
- **Suggestions** - When stuck, AI proposes approaches based on similar scenarios
- **Documentation** - Creating thorough writeups that capture the reasoning behind each step
- **Defense perspective** - Adding context on how each vulnerability can be prevented

The writeups here show what happens when hands-on testing combines with AI's ability to explain and document. Human intuition plus AI assistance.

## Writeup Format

Each writeup includes:
- Executive Summary - Overview of the attack chain
- Phase-by-Phase Breakdown - What we did and why
- Defense Recommendations - How to prevent each vulnerability
- MITRE ATT&CK Mapping - Techniques mapped to the framework
- Tools & Techniques - Explanation of tools used
- Attack Path Diagram - Visual representation of the attack

## Study Questions

Each machine has a Q&A document with:
- Questions at Basic, Intermediate, and Advanced levels
- "Why" questions, not just recall
- Scenario-based application questions
- Answers at the bottom for self-testing
- Scoring guide to track progress

## Completed Machines

| Machine | Difficulty | Key Techniques | Writeup | Q&A |
|---------|------------|----------------|---------|-----|
| Facts | Easy | Path Traversal, SSH Key Cracking, Facter sudo abuse | [Writeup](MACHINES/Facts/Facts_Educational_writeup.md) | [Study Questions](MACHINES/Facts/Facts_Study_Questions.md) |

## How to Use This

**For Learning:**
1. Read the writeup thoroughly
2. Note techniques you haven't seen before
3. Test yourself with study questions (try before checking answers)
4. Review areas where you scored low

**For Practice:**
1. Spawn the machine on HackTheBox
2. Try solving it with just the attack chain summary
3. Compare your approach to the documented method

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Network reconnaissance |
| curl | HTTP requests and web exploitation |
| John the Ripper | Offline password cracking |
| Hashcat | GPU-accelerated cracking |
| Burp Suite | Web application testing |
| ssh2john | SSH key hash extraction |
| LinPEAS/WinPEAS | Privilege escalation enumeration |

## MITRE ATT&CK

Writeups map techniques to the [MITRE ATT&CK Framework](https://attack.mitre.org/):
- Initial Access - First foothold
- Credential Access - Obtaining credentials
- Privilege Escalation - User to root/admin

## Disclaimer

These writeups are for educational purposes only. Use these techniques only on:
- Systems you own
- Systems you have permission to test
- CTF and lab environments like HackTheBox

Unauthorized access is illegal. Practice ethical hacking.
