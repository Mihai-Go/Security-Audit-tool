# Security Audit Tool for macOS

Comprehensive security assessment tool that checks 15+ security controls and generates detailed reports for macOS systems.

## Overview

This tool automates security audits on macOS endpoints, checking critical security controls including firewall configuration, disk encryption, system integrity protection, and more. Perfect for IT helpdesk, security operations, and system administrators.

## What It Does

Automatically checks:
- Firewall configuration and status
- FileVault disk encryption
- Gatekeeper and code signing
- System Integrity Protection (SIP)
- Automatic updates configuration
- Password policies
- Remote access services (SSH, Screen Sharing, File Sharing)
- Open network connections
- Suspicious processes and ports
- Browser security settings
- Failed login attempts
- Antivirus detection (Sophos, Malwarebytes)
- Kernel extensions
- User account security
- Privilege escalation vulnerabilities

## Installation

### Step 1: Download
Download the `security-audit.sh` file to your Mac.

### Step 2: Make Executable
Open Terminal and run:
```bash
chmod +x security-audit.sh
```

### Step 3: Run
```bash
# Basic terminal output
./security-audit.sh

# Generate HTML report
./security-audit.sh -o report.html
```

## Usage Examples

### Example 1: Quick Security Check
```bash
./security-audit.sh
```

This will display results directly in the terminal with color-coded status:
- GREEN (PASS) - Security control is properly configured
- RED (FAIL) - Security issue detected
- YELLOW (WARN) - Warning or recommendation
- BLUE (INFO) - Informational message

### Example 2: Generate HTML Report
```bash
./security-audit.sh -o security-report.html
```

This creates a professional HTML report that you can:
- Open in any web browser
- Email to your manager
- Include in compliance documentation
- Save for audit records

### Example 3: Run with Elevated Privileges
Some checks provide more detail with sudo:
```bash
sudo ./security-audit.sh -o detailed-report.html
```

## Understanding the Output

### Terminal Output Format
```
================================================
    macOS Security Audit Tool v1.0
================================================

--- Firewall Configuration ---
[PASS] Firewall is enabled
[INFO] Firewall allows configured connections

--- Disk Encryption ---
[PASS] FileVault is enabled

--- User Accounts ---
[WARN] 3 administrator accounts
[PASS] No accounts with empty passwords
```

### Status Indicators
- **[PASS]** - Good! This security control is properly configured
- **[FAIL]** - Action required! Security issue found
- **[WARN]** - Review recommended, potential issue
- **[INFO]** - Informational, for your awareness

## Requirements

- macOS 12.0 (Monterey) or later
- Zsh shell (default on modern macOS)
- No additional software needed

## Use Cases

### For IT Helpdesk (L1/L2)
- Quickly verify user system security before granting access
- Troubleshoot security-related issues
- Generate reports for ticket documentation
- Verify compliance with company policies

### For Security Teams
- Routine security audits
- Incident investigation
- Baseline security assessment
- Fleet security monitoring

### For System Administrators
- Pre-deployment verification
- Policy enforcement checks
- Compliance documentation
- Security posture tracking

## Sample Output

```
================================================
    macOS Security Audit Tool v1.0
================================================

--- Firewall Configuration ---
[PASS] Firewall is enabled
[INFO] Firewall allows configured connections

--- Disk Encryption ---
[PASS] FileVault is enabled

--- Gatekeeper & Code Signing ---
[PASS] Gatekeeper is enabled

--- System Integrity Protection ---
[PASS] SIP is enabled

--- Software Updates ---
[PASS] Automatic update check enabled
[PASS] System is up to date

--- Password & Authentication ---
[PASS] Password policy configured
[PASS] Screen lock on wake enabled

--- Remote Access & Sharing ---
[PASS] SSH (Remote Login) is disabled
[PASS] Screen Sharing is disabled
[PASS] File Sharing is disabled

--- Network Security ---
[INFO] Found 12 listening services

--- User Accounts ---
[PASS] 2 administrator account(s)
[PASS] No accounts with empty passwords

--- Security Software ---
[PASS] Sophos Endpoint Protection detected

Audit completed at 2024-02-17 14:30:22
Security audit complete!
```

## Customization

You can edit the script to adjust thresholds. Open the script and find:

```bash
# Customize these values
FAILED_LOGIN_THRESHOLD=10
ADMIN_USER_MAX=2
```

Change the numbers to match your organization's policies.

## Troubleshooting

### Problem: "Permission denied"
**Solution:**
```bash
chmod +x security-audit.sh
```

### Problem: "Command not found"
**Solution:** You need to be in the same directory as the script:
```bash
cd ~/Downloads  # or wherever you saved it
./security-audit.sh
```

### Problem: HTML report won't open
**Solution:** Right-click the HTML file and select "Open With" > "Safari" (or any browser)

## Security Considerations

- This tool only reads system information, it does not make changes
- Some checks provide more detail when run with sudo
- Generated reports may contain sensitive information - handle appropriately
- HTML reports should be stored securely

## Interview Talking Points

If discussing this project in an interview:

**What problem does it solve?**
"Manual security checks are time-consuming and error-prone. This tool automates the process, ensuring consistent audits and saving helpdesk time."

**Why this approach?**
"I used shell scripting because it's native to macOS, requires no additional software, and can be easily deployed across an organization."

**Real-world application:**
"In L1 helpdesk, you often need to quickly verify a user's security posture. This tool provides that information in seconds instead of manually checking 15+ settings."

**Sophos relevance:**
"The tool specifically checks for Sophos Endpoint Protection, showing I understand how endpoint security tools integrate with the OS."

## Future Enhancements

Potential improvements:
- Integration with Sophos Central API
- Automated remediation suggestions
- Email alerting capabilities
- JSON output for SIEM integration
- Scheduled execution support

## Author

Goanta Mihai
- Email: Goanta.Mihai@proton.me
- GitHub: https://github.com/Mihai-Go
- LinkedIn: www.linkedin.com/in/mihai-goanță-416242336
## Version

Version 1.0 - February 2026

## License

MIT License

Copyright (c) 2026 Goanta Mihai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer

This tool is for authorised security testing only. Always obtain proper authorisation before running security tools on systems you don't own or manage.

## Support

For issues or questions:
- Open an issue on GitHub
- Email: Goanta.Mihai@proton.me

## Acknowledgments

Built with macOS security best practices from:
- Apple Security Documentation
- NIST macOS Security Compliance Project
- MITRE ATT&CK Framework
