#!/bin/zsh

################################################################################
# macOS Security Audit Script
# Author: Goanta Mihai
# Description: Performs comprehensive security checks on macOS systems
# Usage: ./security-audit.sh [-o output.html]
################################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output file
OUTPUT_FILE=""
HTML_OUTPUT=false

# Parse arguments
while getopts "o:" opt; do
    case $opt in
        o)
            OUTPUT_FILE="$OPTARG"
            HTML_OUTPUT=true
            ;;
        \?)
            echo "Usage: $0 [-o output.html]"
            exit 1
            ;;
    esac
done

echo "${BLUE}================================================${NC}"
echo "${BLUE}    macOS Security Audit Tool v1.0${NC}"
echo "${BLUE}================================================${NC}\n"

# Initialize HTML output
if [ "$HTML_OUTPUT" = true ]; then
    cat > "$OUTPUT_FILE" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>macOS Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .warn { color: #f39c12; font-weight: bold; }
        .info { color: #3498db; font-weight: bold; }
        .check { background: #ecf0f1; padding: 10px; margin: 10px 0; border-left: 4px solid #95a5a6; border-radius: 4px; }
        .metadata { background: #e8f4f8; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat { text-align: center; padding: 15px; background: #ecf0f1; border-radius: 8px; }
        .stat-value { font-size: 2em; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 macOS Security Audit Report</h1>
    <div class="metadata">
        <strong>System:</strong> $(hostname)<br>
        <strong>Date:</strong> $(date)<br>
        <strong>User:</strong> $(whoami)<br>
        <strong>macOS Version:</strong> $(sw_vers -productVersion)
    </div>
EOF
fi

# Function to log results
log_result() {
    local status=$1
    local message=$2
    local detail=$3
    
    case $status in
        "PASS")
            echo "${GREEN}[✓]${NC} $message"
            [ "$HTML_OUTPUT" = true ] && echo "<div class='check'><span class='pass'>✓ PASS:</span> $message<br><small>$detail</small></div>" >> "$OUTPUT_FILE"
            ;;
        "FAIL")
            echo "${RED}[✗]${NC} $message"
            [ "$HTML_OUTPUT" = true ] && echo "<div class='check'><span class='fail'>✗ FAIL:</span> $message<br><small>$detail</small></div>" >> "$OUTPUT_FILE"
            ;;
        "WARN")
            echo "${YELLOW}[!]${NC} $message"
            [ "$HTML_OUTPUT" = true ] && echo "<div class='check'><span class='warn'>! WARN:</span> $message<br><small>$detail</small></div>" >> "$OUTPUT_FILE"
            ;;
        "INFO")
            echo "${BLUE}[i]${NC} $message"
            [ "$HTML_OUTPUT" = true ] && echo "<div class='check'><span class='info'>ℹ INFO:</span> $message<br><small>$detail</small></div>" >> "$OUTPUT_FILE"
            ;;
    esac
}

section_header() {
    echo "\n${BLUE}━━━ $1 ━━━${NC}"
    [ "$HTML_OUTPUT" = true ] && echo "<h2>$1</h2>" >> "$OUTPUT_FILE"
}

# 1. Firewall Status
section_header "Firewall Configuration"

if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
    log_result "PASS" "Firewall is enabled" "System firewall is active and protecting network connections"
else
    log_result "FAIL" "Firewall is disabled" "Enable via: System Settings > Network > Firewall"
fi

if /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall | grep -q "enabled"; then
    log_result "WARN" "Firewall blocking all incoming connections" "May block legitimate services"
else
    log_result "INFO" "Firewall allows configured connections" "Review allowed applications regularly"
fi

# 2. FileVault Encryption
section_header "Disk Encryption"

if fdesetup status | grep -q "On"; then
    log_result "PASS" "FileVault is enabled" "Full disk encryption is active"
else
    log_result "FAIL" "FileVault is disabled" "Enable via: System Settings > Privacy & Security > FileVault"
fi

# 3. Gatekeeper
section_header "Gatekeeper & Code Signing"

gatekeeper_status=$(spctl --status 2>&1)
if echo "$gatekeeper_status" | grep -q "assessments enabled"; then
    log_result "PASS" "Gatekeeper is enabled" "System validates app signatures before execution"
else
    log_result "FAIL" "Gatekeeper is disabled" "Enable via: sudo spctl --master-enable"
fi

# 4. System Integrity Protection (SIP)
section_header "System Integrity Protection"

if csrutil status | grep -q "enabled"; then
    log_result "PASS" "SIP is enabled" "Kernel and system files are protected"
else
    log_result "WARN" "SIP is disabled" "Only disable if absolutely necessary for development"
fi

# 5. Automatic Updates
section_header "Software Updates"

auto_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "0")
if [ "$auto_update" = "1" ]; then
    log_result "PASS" "Automatic update check enabled" "System checks for updates automatically"
else
    log_result "FAIL" "Automatic update check disabled" "Enable via: System Settings > General > Software Update"
fi

# Check for pending updates
pending_updates=$(softwareupdate -l 2>&1)
if echo "$pending_updates" | grep -q "No new software available"; then
    log_result "PASS" "System is up to date" "No pending security updates"
else
    log_result "WARN" "Updates available" "Run: softwareupdate -ia to install all"
fi

# 6. Password Policy
section_header "Password & Authentication"

pwpolicy_output=$(pwpolicy -getaccountpolicies 2>&1)
if echo "$pwpolicy_output" | grep -q "policyAttributePassword"; then
    log_result "PASS" "Password policy configured" "System enforces password requirements"
else
    log_result "WARN" "No password policy detected" "Consider setting minimum password requirements"
fi

# Check screen lock
screensaver_delay=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "0")
if [ "$screensaver_delay" = "1" ]; then
    log_result "PASS" "Screen lock on wake enabled" "System requires password after sleep/screensaver"
else
    log_result "FAIL" "Screen lock not configured" "Enable via: System Settings > Lock Screen"
fi

# 7. Remote Access Services
section_header "Remote Access & Sharing"

ssh_enabled=$(systemsetup -getremotelogin 2>/dev/null | grep -c "On" || echo "0")
if [ "$ssh_enabled" = "0" ]; then
    log_result "PASS" "SSH (Remote Login) is disabled" "Reduces attack surface"
else
    log_result "WARN" "SSH is enabled" "Ensure strong authentication and monitor access"
fi

# Check screen sharing
screen_sharing=$(launchctl list | grep -c "com.apple.screensharing" || echo "0")
if [ "$screen_sharing" = "0" ]; then
    log_result "PASS" "Screen Sharing is disabled" "Reduces attack surface"
else
    log_result "INFO" "Screen Sharing is enabled" "Verify only authorized users have access"
fi

# Check file sharing
file_sharing=$(launchctl list | grep -c "com.apple.smbd" || echo "0")
if [ "$file_sharing" = "0" ]; then
    log_result "PASS" "File Sharing is disabled" "Reduces attack surface"
else
    log_result "INFO" "File Sharing is enabled" "Review shared folders and permissions"
fi

# 8. Open Network Connections
section_header "Network Security"

[ "$HTML_OUTPUT" = true ] && echo "<h3>Active Network Connections</h3><table><tr><th>Protocol</th><th>Local Address</th><th>Foreign Address</th><th>State</th><th>Process</th></tr>" >> "$OUTPUT_FILE"

listening_ports=$(lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | tail -n +2)
if [ -n "$listening_ports" ]; then
    log_result "INFO" "Found $(echo "$listening_ports" | wc -l | tr -d ' ') listening services" "Review open ports below"
    
    if [ "$HTML_OUTPUT" = true ]; then
        echo "$listening_ports" | while IFS= read -r line; do
            process=$(echo "$line" | awk '{print $1}')
            address=$(echo "$line" | awk '{print $9}')
            echo "<tr><td>TCP</td><td>$address</td><td>-</td><td>LISTEN</td><td>$process</td></tr>" >> "$OUTPUT_FILE"
        done
    fi
fi

[ "$HTML_OUTPUT" = true ] && echo "</table>" >> "$OUTPUT_FILE"

# 9. Suspicious Processes
section_header "Process Analysis"

# Check for processes listening on common attack ports
suspicious_ports="4444 5555 6666 7777 8888 31337"
for port in $suspicious_ports; do
    if lsof -i ":$port" >/dev/null 2>&1; then
        process=$(lsof -i ":$port" | tail -n 1 | awk '{print $1}')
        log_result "WARN" "Suspicious port $port in use by $process" "Investigate this process"
    fi
done

# 10. Browser Security (Safari)
section_header "Browser Security"

# Safari security settings
safari_warn_fraud=$(defaults read com.apple.Safari WarnAboutFraudulentWebsites 2>/dev/null || echo "0")
if [ "$safari_warn_fraud" = "1" ]; then
    log_result "PASS" "Safari fraudulent site warnings enabled" "Protection against phishing sites"
else
    log_result "WARN" "Safari fraudulent site warnings disabled" "Enable for better protection"
fi

# 11. System Logs Check
section_header "Security Log Analysis"

# Check for failed login attempts
failed_logins=$(log show --predicate 'eventMessage contains "Authentication failed"' --last 24h 2>/dev/null | wc -l | tr -d ' ')
if [ "$failed_logins" -gt 10 ]; then
    log_result "WARN" "$failed_logins failed login attempts in last 24h" "Potential brute force attempt detected"
else
    log_result "PASS" "Low failed login attempts ($failed_logins)" "Normal authentication patterns"
fi

# 12. Installed Security Software
section_header "Security Software"

antivirus_found=false
if [ -d "/Applications/Sophos" ] || [ -d "/Library/Application Support/Sophos" ]; then
    log_result "PASS" "Sophos Endpoint Protection detected" "Enterprise antivirus installed"
    antivirus_found=true
fi

if [ -d "/Applications/Malwarebytes.app" ]; then
    log_result "INFO" "Malwarebytes detected" "Additional malware protection installed"
    antivirus_found=true
fi

if [ "$antivirus_found" = false ]; then
    log_result "WARN" "No commercial antivirus detected" "Consider installing endpoint protection"
fi

# 13. Kernel Extensions
section_header "Kernel Extensions & System Extensions"

kexts=$(kextstat | grep -v "com.apple" | tail -n +2)
if [ -n "$kexts" ]; then
    kext_count=$(echo "$kexts" | wc -l | tr -d ' ')
    log_result "INFO" "$kext_count third-party kernel extensions loaded" "Review for legitimacy"
    
    if [ "$HTML_OUTPUT" = true ]; then
        echo "<h3>Third-Party Kernel Extensions</h3><table><tr><th>Bundle ID</th></tr>" >> "$OUTPUT_FILE"
        echo "$kexts" | awk '{print $6}' | while read -r kext; do
            echo "<tr><td>$kext</td></tr>" >> "$OUTPUT_FILE"
        done
        echo "</table>" >> "$OUTPUT_FILE"
    fi
fi

# 14. User Account Security
section_header "User Accounts"

admin_users=$(dscl . -read /Groups/admin GroupMembership | cut -d: -f2)
admin_count=$(echo "$admin_users" | wc -w | tr -d ' ')

if [ "$admin_count" -le 2 ]; then
    log_result "PASS" "$admin_count administrator account(s)" "Limited admin privileges"
else
    log_result "WARN" "$admin_count administrator accounts" "Review if all users need admin rights"
fi

# Check for users with empty passwords
users_with_no_pwd=$(dscl . list /Users | while read user; do
    if dscl . -authonly "$user" "" 2>/dev/null; then
        echo "$user"
    fi
done)

if [ -z "$users_with_no_pwd" ]; then
    log_result "PASS" "No accounts with empty passwords" "All accounts require authentication"
else
    log_result "FAIL" "Accounts with empty passwords found" "Set passwords immediately"
fi

# 15. Sudo Configuration
section_header "Privilege Escalation"

if [ -f /etc/sudoers ]; then
    if grep -q "NOPASSWD" /etc/sudoers 2>/dev/null; then
        log_result "WARN" "Passwordless sudo configured for some users" "Review /etc/sudoers configuration"
    else
        log_result "PASS" "Sudo requires password" "Standard security configuration"
    fi
fi

# Summary
section_header "Audit Summary"

echo "${BLUE}Audit completed at $(date)${NC}"
echo "${BLUE}Review the findings above and take appropriate action.${NC}\n"

# Close HTML
if [ "$HTML_OUTPUT" = true ]; then
    cat >> "$OUTPUT_FILE" << 'EOF'
    <div class="metadata" style="margin-top: 30px;">
        <strong>Report Generated:</strong> <script>document.write(new Date().toLocaleString());</script><br>
        <strong>Tool:</strong> macOS Security Audit Script v1.0
    </div>
</div>
</body>
</html>
EOF
    echo "${GREEN}HTML report saved to: $OUTPUT_FILE${NC}"
fi

echo "${GREEN}Security audit complete!${NC}"
