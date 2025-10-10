# CRECON - Advanced Reconnaissance Tool

![Termux Compatible](https://img.shields.io/badge/Termux-Compatible-brightgreen)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)

A comprehensive security reconnaissance tool for authorized penetration testing and security assessments.

## Quick Start (Termux)

```bash
# Update and install dependencies
pkg update && pkg upgrade
pkg install python git nmap
pip install requests beautifulsoup4 dnspython cryptography

# Download and run
git clone https://github.com/your-repo/crecon.git
cd crecon
chmod +x crecon.py
./crecon.py example.com
```

## Features

 🔍 DNS Enumeration - Complete DNS record analysis

 🌐 Subdomain Discovery - Multi-threaded subdomain scanning

 🔒 Port Scanning - NMAP integration with stealth mode

 🕸️ Web Crawling - Website structure and form analysis

 📊 Vulnerability Assessment - Security header checks

 🔐 SSL/TLS Analysis - Certificate validation

 🛡️ WAF Detection - Identify protection systems

 📄 Multi-format Reports - JSON and HTML outputs

## Basic Usage

```bash
# Basic scan
./crecon.py target.com

# Stealth mode
./crecon.py target.com --stealth

# Custom output directory
./crecon.py target.com --output ./reports
```

## Output

Reports are saved in the reports/ directory:

• advanced_recon_target_timestamp.json - Detailed JSON data

• advanced_recon_target_timestamp.html - Formatted HTML report

## Legal Notice

FOR AUTHORIZED TESTING ONLY

• Only scan systems you own or have explicit permission to test

• Unauthorized scanning may be illegal in your jurisdiction

• Use responsibly and ethically

## Requirements

• Python 3.6+

• Linux (Termux for Android)

• Basic dependencies: requests, beautifulsoup4, dnspython, cryptography

## Troubleshooting

NMAP issues on Termux:

```bash
pkg install nmap
pip install python-nmap
```

SSL errors:

```bash
./crecon.py target.com --no-verify
```

Permission denied:

```bash
chmod +x crecon.py
termux-setup-storage
```

## Support

· Issues: GitHub repository

· Documentation: In-code comments and examples



`CRECON - Advanced reconnaissance for security professionals`

`Use responsibly. Test ethically. Secure proactively.`
