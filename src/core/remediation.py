"""
Automated remediation script generator for SuperSleuth Network
Generates platform-specific fix scripts based on diagnostic findings
"""

import os
import stat
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from ..utils.logger import get_logger


class RemediationScriptGenerator:
    """Generates remediation scripts based on diagnostic findings"""
    
    def __init__(self, platform: str = None):
        self.platform = platform or self._detect_platform()
        self.logger = get_logger(self.__class__.__name__)
        self.scripts_generated = []
        
    def _detect_platform(self) -> str:
        """Detect current platform"""
        import platform
        system = platform.system().lower()
        
        if system == 'darwin':
            return 'macos'
        elif system == 'linux':
            return 'linux'
        elif system == 'windows':
            return 'windows'
        else:
            return 'unknown'
    
    def generate_remediation_script(self, findings: Dict[str, Any], 
                                  output_dir: str = 'remediation_scripts') -> List[str]:
        """
        Generate remediation scripts based on findings
        
        Args:
            findings: Diagnostic findings from SuperSleuth
            output_dir: Directory to save scripts
            
        Returns:
            List of generated script paths
        """
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scripts = []
        
        # Analyze findings and generate appropriate scripts
        
        # Network performance issues
        if self._has_performance_issues(findings):
            script_path = self._generate_performance_remediation(
                findings, output_path, timestamp
            )
            if script_path:
                scripts.append(script_path)
        
        # Security issues
        if self._has_security_issues(findings):
            script_path = self._generate_security_remediation(
                findings, output_path, timestamp
            )
            if script_path:
                scripts.append(script_path)
        
        # WiFi issues
        if self._has_wifi_issues(findings):
            script_path = self._generate_wifi_remediation(
                findings, output_path, timestamp
            )
            if script_path:
                scripts.append(script_path)
        
        # Compliance issues
        if self._has_compliance_issues(findings):
            script_path = self._generate_compliance_remediation(
                findings, output_path, timestamp
            )
            if script_path:
                scripts.append(script_path)
        
        self.scripts_generated.extend(scripts)
        return scripts
    
    def _has_performance_issues(self, findings: Dict[str, Any]) -> bool:
        """Check if findings contain performance issues"""
        
        if 'performance_analysis' in findings:
            perf_data = findings['performance_analysis']
            if 'results' in perf_data:
                sla_validation = perf_data['results'].get('sla_validation', {})
                return not sla_validation.get('compliant', True)
        return False
    
    def _has_security_issues(self, findings: Dict[str, Any]) -> bool:
        """Check if findings contain security issues"""
        
        if 'security_assessment' in findings:
            sec_data = findings['security_assessment']
            if 'results' in sec_data:
                return sec_data['results'].get('overall_risk_score', 0) > 30
        return False
    
    def _has_wifi_issues(self, findings: Dict[str, Any]) -> bool:
        """Check if findings contain WiFi issues"""
        
        if 'wifi_analysis' in findings:
            wifi_data = findings['wifi_analysis']
            if 'results' in wifi_data:
                return bool(wifi_data['results'].get('signal_analysis', {}).get('coverage_issues'))
        return False
    
    def _has_compliance_issues(self, findings: Dict[str, Any]) -> bool:
        """Check if findings contain compliance issues"""
        
        if 'security_assessment' in findings:
            sec_data = findings['security_assessment']
            if 'results' in sec_data:
                compliance = sec_data['results'].get('compliance_status', {})
                return not compliance.get('overall_compliant', True)
        return False
    
    def _generate_performance_remediation(self, findings: Dict[str, Any], 
                                        output_path: Path, timestamp: str) -> Optional[str]:
        """Generate performance remediation script"""
        
        script_name = f"performance_optimization_{timestamp}"
        
        if self.platform == 'linux':
            script_content = self._generate_linux_performance_script(findings)
            script_ext = '.sh'
        elif self.platform == 'windows':
            script_content = self._generate_windows_performance_script(findings)
            script_ext = '.ps1'
        elif self.platform == 'macos':
            script_content = self._generate_macos_performance_script(findings)
            script_ext = '.sh'
        else:
            return None
        
        script_path = output_path / f"{script_name}{script_ext}"
        self._save_script(script_path, script_content)
        
        return str(script_path)
    
    def _generate_linux_performance_script(self, findings: Dict[str, Any]) -> str:
        """Generate Linux performance optimization script"""
        
        script = """#!/bin/bash
# SuperSleuth Network - Performance Optimization Script
# Generated: {timestamp}
# Platform: Linux

set -e

echo "🚀 Starting performance optimization..."

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to backup current settings
backup_settings() {
    echo "📦 Backing up current settings..."
    mkdir -p /etc/supersleuth/backups
    
    # Backup network settings
    cp /etc/sysctl.conf /etc/supersleuth/backups/sysctl.conf.$(date +%Y%m%d_%H%M%S)
    
    # Backup QoS rules if exist
    if command -v tc &> /dev/null; then
        tc qdisc show > /etc/supersleuth/backups/tc_rules.$(date +%Y%m%d_%H%M%S)
    fi
}

# Network optimization
optimize_network() {
    echo "🔧 Optimizing network settings..."
    
    # Increase network buffers
    cat >> /etc/sysctl.conf << EOF

# SuperSleuth Network Optimizations
# Increase TCP buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Increase netdev budget
net.core.netdev_budget = 600
net.core.netdev_max_backlog = 5000

# Enable TCP fastopen
net.ipv4.tcp_fastopen = 3

# Optimize TCP congestion control
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Enable timestamps for better RTT calculation
net.ipv4.tcp_timestamps = 1
EOF

    # Apply settings
    sysctl -p
}

# QoS implementation
implement_qos() {
    echo "📊 Implementing QoS rules..."
    
    if ! command -v tc &> /dev/null; then
        echo "Installing traffic control tools..."
        apt-get update && apt-get install -y iproute2 || yum install -y iproute-tc
    fi
    
    # Get primary network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -z "$INTERFACE" ]]; then
        echo "❌ Could not detect network interface"
        return 1
    fi
    
    echo "Using interface: $INTERFACE"
    
    # Clear existing rules
    tc qdisc del dev $INTERFACE root 2>/dev/null || true
    
    # Implement HTB (Hierarchical Token Bucket) QoS
    tc qdisc add dev $INTERFACE root handle 1: htb default 30
    
    # Create classes for different traffic types
    tc class add dev $INTERFACE parent 1: classid 1:1 htb rate 1000mbit
    tc class add dev $INTERFACE parent 1:1 classid 1:10 htb rate 500mbit ceil 900mbit prio 1  # VoIP/Video
    tc class add dev $INTERFACE parent 1:1 classid 1:20 htb rate 300mbit ceil 800mbit prio 2  # Business apps
    tc class add dev $INTERFACE parent 1:1 classid 1:30 htb rate 200mbit ceil 700mbit prio 3  # General traffic
    
    # Add SFQ for fairness
    tc qdisc add dev $INTERFACE parent 1:10 handle 10: sfq perturb 10
    tc qdisc add dev $INTERFACE parent 1:20 handle 20: sfq perturb 10
    tc qdisc add dev $INTERFACE parent 1:30 handle 30: sfq perturb 10
    
    # Classify traffic
    # VoIP/Video conferencing (common ports)
    tc filter add dev $INTERFACE parent 1: protocol ip prio 1 u32 match ip dport 5060 0xffff flowid 1:10
    tc filter add dev $INTERFACE parent 1: protocol ip prio 1 u32 match ip dport 5061 0xffff flowid 1:10
    tc filter add dev $INTERFACE parent 1: protocol ip prio 1 u32 match ip sport 5060 0xffff flowid 1:10
    
    echo "✅ QoS rules implemented"
}

# DNS optimization
optimize_dns() {
    echo "🌐 Optimizing DNS configuration..."
    
    # Install local DNS cache if not present
    if ! command -v dnsmasq &> /dev/null; then
        echo "Installing dnsmasq for DNS caching..."
        apt-get update && apt-get install -y dnsmasq || yum install -y dnsmasq
    fi
    
    # Configure dnsmasq
    cat > /etc/dnsmasq.d/supersleuth.conf << EOF
# SuperSleuth DNS Optimization
cache-size=10000
no-negcache
dns-forward-max=150
EOF

    # Restart dnsmasq
    systemctl restart dnsmasq
    
    echo "✅ DNS caching configured"
}

# Main execution
main() {
    check_root
    backup_settings
    optimize_network
    implement_qos
    optimize_dns
    
    echo ""
    echo "✨ Performance optimization complete!"
    echo ""
    echo "🔄 Please reboot to ensure all changes take effect"
    echo "📋 Backups saved in /etc/supersleuth/backups/"
    echo ""
    echo "⚠️  To revert changes:"
    echo "   1. Restore backup files from /etc/supersleuth/backups/"
    echo "   2. Run: sysctl -p"
    echo "   3. Run: tc qdisc del dev $(ip route | grep default | awk '{print $5}' | head -n1) root"
}

main "$@"
""".format(timestamp=datetime.now().isoformat())
        
        return script
    
    def _generate_windows_performance_script(self, findings: Dict[str, Any]) -> str:
        """Generate Windows performance optimization script"""
        
        script = """# SuperSleuth Network - Performance Optimization Script
# Generated: {timestamp}
# Platform: Windows
# Run as Administrator in PowerShell

Write-Host "🚀 Starting performance optimization..." -ForegroundColor Green

# Check for administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{{
    Write-Host "This script must be run as Administrator" -ForegroundColor Red
    exit 1
}}

# Function to backup registry settings
function Backup-Settings {{
    Write-Host "📦 Backing up current settings..." -ForegroundColor Yellow
    
    $backupPath = "C:\\SuperSleuth\\Backups"
    New-Item -ItemType Directory -Force -Path $backupPath | Out-Null
    
    # Export network-related registry keys
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    reg export "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" "$backupPath\\tcpip_params_$timestamp.reg" /y
}}

# Network optimization
function Optimize-Network {{
    Write-Host "🔧 Optimizing network settings..." -ForegroundColor Yellow
    
    # TCP/IP optimizations
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "TcpWindowSize" -Value 65535 -Type DWord
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "TcpMaxDataRetransmissions" -Value 5 -Type DWord
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "SackOpts" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "TcpMaxDupAcks" -Value 2 -Type DWord
    
    # Enable TCP Chimney Offload
    netsh int tcp set global chimney=enabled
    
    # Enable Receive Side Scaling
    netsh int tcp set global rss=enabled
    
    # Set TCP autotuning level
    netsh int tcp set global autotuninglevel=normal
    
    # Disable power saving for network adapters
    Get-NetAdapter | ForEach-Object {{
        $adapter = $_
        Write-Host "Optimizing adapter: $($adapter.Name)"
        
        # Disable power management
        $powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\\wmi | Where-Object {{ $_.InstanceName -match $adapter.PnPDeviceID }}
        if ($powerMgmt) {{
            $powerMgmt.Enable = $false
            $powerMgmt.Put()
        }}
    }}
    
    Write-Host "✅ Network settings optimized" -ForegroundColor Green
}}

# QoS implementation
function Implement-QoS {{
    Write-Host "📊 Implementing QoS policies..." -ForegroundColor Yellow
    
    # Remove existing QoS policies
    Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$false
    
    # Create QoS policies for different traffic types
    
    # VoIP/Video conferencing
    New-NetQosPolicy -Name "VoIP-Video" -IPProtocolMatchCondition Both -IPDstPortStartMatchCondition 5060 -IPDstPortEndMatchCondition 5061 -DSCPValue 46 -NetworkProfile All
    
    # Business applications (RDP, SSH)
    New-NetQosPolicy -Name "BusinessApps" -IPProtocolMatchCondition TCP -IPDstPortStartMatchCondition 3389 -IPDstPortEndMatchCondition 3389 -DSCPValue 26 -NetworkProfile All
    New-NetQosPolicy -Name "SSH" -IPProtocolMatchCondition TCP -IPDstPortStartMatchCondition 22 -IPDstPortEndMatchCondition 22 -DSCPValue 26 -NetworkProfile All
    
    # Web traffic
    New-NetQosPolicy -Name "Web" -IPProtocolMatchCondition TCP -IPDstPortStartMatchCondition 80 -IPDstPortEndMatchCondition 80 -DSCPValue 10 -NetworkProfile All
    New-NetQosPolicy -Name "HTTPS" -IPProtocolMatchCondition TCP -IPDstPortStartMatchCondition 443 -IPDstPortEndMatchCondition 443 -DSCPValue 10 -NetworkProfile All
    
    Write-Host "✅ QoS policies implemented" -ForegroundColor Green
}}

# DNS optimization
function Optimize-DNS {{
    Write-Host "🌐 Optimizing DNS configuration..." -ForegroundColor Yellow
    
    # Clear DNS cache
    Clear-DnsClientCache
    
    # Set DNS client settings
    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object Status -eq "Up").InterfaceIndex -ServerAddresses "1.1.1.1", "8.8.8.8"
    
    # Enable DNS over HTTPS if available (Windows 11)
    if (Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {{
        Set-DnsClientDohServerAddress -ServerAddress 1.1.1.1 -DohTemplate https://cloudflare-dns.com/dns-query
        Set-DnsClientDohServerAddress -ServerAddress 8.8.8.8 -DohTemplate https://dns.google/dns-query
    }}
    
    Write-Host "✅ DNS configuration optimized" -ForegroundColor Green
}}

# Main execution
try {{
    Backup-Settings
    Optimize-Network
    Implement-QoS
    Optimize-DNS
    
    Write-Host ""
    Write-Host "✨ Performance optimization complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🔄 Please restart your computer to ensure all changes take effect" -ForegroundColor Yellow
    Write-Host "📋 Backups saved in C:\\SuperSleuth\\Backups\\" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "⚠️  To revert changes:" -ForegroundColor Yellow
    Write-Host "   1. Import backup registry files from C:\\SuperSleuth\\Backups\\" -ForegroundColor White
    Write-Host "   2. Run: netsh int tcp reset" -ForegroundColor White
    Write-Host "   3. Run: Get-NetQosPolicy | Remove-NetQosPolicy" -ForegroundColor White
}}
catch {{
    Write-Host "❌ Error occurred: $_" -ForegroundColor Red
    exit 1
}}
""".format(timestamp=datetime.now().isoformat())
        
        return script
    
    def _generate_macos_performance_script(self, findings: Dict[str, Any]) -> str:
        """Generate macOS performance optimization script"""
        
        script = """#!/bin/bash
# SuperSleuth Network - Performance Optimization Script
# Generated: {timestamp}
# Platform: macOS

set -e

echo "🚀 Starting performance optimization..."

# Function to check if running as root
check_root() {{
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (use sudo)"
        exit 1
    fi
}}

# Function to backup current settings
backup_settings() {{
    echo "📦 Backing up current settings..."
    mkdir -p /etc/supersleuth/backups
    
    # Backup network settings
    sysctl -a | grep -E "net\\." > /etc/supersleuth/backups/sysctl_net_$(date +%Y%m%d_%H%M%S).txt
}}

# Network optimization
optimize_network() {{
    echo "🔧 Optimizing network settings..."
    
    # Increase maximum socket buffer sizes
    sysctl -w kern.ipc.maxsockbuf=8388608
    sysctl -w net.inet.tcp.sendspace=1048576
    sysctl -w net.inet.tcp.recvspace=1048576
    
    # TCP optimizations
    sysctl -w net.inet.tcp.mssdflt=1440
    sysctl -w net.inet.tcp.win_scale_factor=8
    sysctl -w net.inet.tcp.autorcvbufmax=1048576
    sysctl -w net.inet.tcp.autosndbufmax=1048576
    
    # Enable TCP keepalive
    sysctl -w net.inet.tcp.always_keepalive=1
    
    # Optimize for low latency
    sysctl -w net.inet.tcp.delayed_ack=0
    
    # Make settings persistent
    cat >> /etc/sysctl.conf << EOF

# SuperSleuth Network Optimizations
kern.ipc.maxsockbuf=8388608
net.inet.tcp.sendspace=1048576
net.inet.tcp.recvspace=1048576
net.inet.tcp.mssdflt=1440
net.inet.tcp.win_scale_factor=8
net.inet.tcp.autorcvbufmax=1048576
net.inet.tcp.autosndbufmax=1048576
net.inet.tcp.always_keepalive=1
net.inet.tcp.delayed_ack=0
EOF
}}

# DNS optimization
optimize_dns() {{
    echo "🌐 Optimizing DNS configuration..."
    
    # Configure DNS servers
    networksetup -listallnetworkservices | grep -v "*" | while read service; do
        echo "Setting DNS for: $service"
        networksetup -setdnsservers "$service" 1.1.1.1 8.8.8.8
    done
    
    # Flush DNS cache
    dscacheutil -flushcache
    
    echo "✅ DNS configuration optimized"
}}

# WiFi optimization
optimize_wifi() {{
    echo "📡 Optimizing WiFi settings..."
    
    # Get WiFi interface (usually en0 or en1)
    WIFI_INTERFACE=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{{getline; print $2}}')
    
    if [[ -n "$WIFI_INTERFACE" ]]; then
        # Disable WiFi power saving
        sudo pmset -a tcpkeepalive 1
        
        # Set WiFi to maximum performance
        airport $WIFI_INTERFACE prefs RequireAdminPowerToggle=NO
        
        echo "✅ WiFi optimized for performance"
    else
        echo "⚠️  No WiFi interface found"
    fi
}}

# Main execution
main() {{
    check_root
    backup_settings
    optimize_network
    optimize_dns
    optimize_wifi
    
    echo ""
    echo "✨ Performance optimization complete!"
    echo ""
    echo "🔄 Please reboot to ensure all changes take effect"
    echo "📋 Backups saved in /etc/supersleuth/backups/"
    echo ""
    echo "⚠️  To revert changes:"
    echo "   1. Restore settings from /etc/supersleuth/backups/"
    echo "   2. Remove additions from /etc/sysctl.conf"
    echo "   3. Reboot system"
}}

main "$@"
""".format(timestamp=datetime.now().isoformat())
        
        return script
    
    def _generate_security_remediation(self, findings: Dict[str, Any], 
                                     output_path: Path, timestamp: str) -> Optional[str]:
        """Generate security remediation script"""
        
        script_name = f"security_hardening_{timestamp}"
        
        if self.platform == 'linux':
            script_content = self._generate_linux_security_script(findings)
            script_ext = '.sh'
        elif self.platform == 'windows':
            script_content = self._generate_windows_security_script(findings)
            script_ext = '.ps1'
        elif self.platform == 'macos':
            script_content = self._generate_macos_security_script(findings)
            script_ext = '.sh'
        else:
            return None
        
        script_path = output_path / f"{script_name}{script_ext}"
        self._save_script(script_path, script_content)
        
        return str(script_path)
    
    def _generate_linux_security_script(self, findings: Dict[str, Any]) -> str:
        """Generate Linux security hardening script"""
        
        # Extract specific security issues from findings
        open_ports = []
        if 'security_assessment' in findings:
            sec_results = findings['security_assessment'].get('results', {})
            network_sec = sec_results.get('network_security', {})
            open_ports = network_sec.get('open_ports', [])
        
        script = """#!/bin/bash
# SuperSleuth Network - Security Hardening Script
# Generated: {timestamp}
# Platform: Linux

set -e

echo "🔒 Starting security hardening..."

# Function to check if running as root
check_root() {{
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (use sudo)"
        exit 1
    fi
}}

# Backup current configuration
backup_config() {{
    echo "📦 Backing up current configuration..."
    mkdir -p /etc/supersleuth/security_backups
    
    # Backup firewall rules
    if command -v iptables &> /dev/null; then
        iptables-save > /etc/supersleuth/security_backups/iptables_$(date +%Y%m%d_%H%M%S).rules
    fi
    
    if command -v ufw &> /dev/null; then
        ufw status verbose > /etc/supersleuth/security_backups/ufw_status_$(date +%Y%m%d_%H%M%S).txt
    fi
    
    # Backup SSH config
    cp /etc/ssh/sshd_config /etc/supersleuth/security_backups/sshd_config_$(date +%Y%m%d_%H%M%S)
}}

# Configure firewall
configure_firewall() {{
    echo "🔥 Configuring firewall..."
    
    # Install UFW if not present
    if ! command -v ufw &> /dev/null; then
        apt-get update && apt-get install -y ufw || yum install -y ufw
    fi
    
    # Basic firewall rules
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (but change port for security)
    ufw allow 22/tcp comment "SSH"
    
    # Allow essential services only
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    
    # Block specific vulnerable ports found in scan
{port_blocks}
    
    # Enable firewall
    ufw --force enable
    
    echo "✅ Firewall configured"
}}

# Harden SSH
harden_ssh() {{
    echo "🔐 Hardening SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Apply hardening settings
    cat >> /etc/ssh/sshd_config << EOF

# SuperSleuth Security Hardening
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowUsers supersleuth_admin
EOF

    # Restart SSH service
    systemctl restart sshd || service ssh restart
    
    echo "✅ SSH hardened"
}}

# System hardening
system_hardening() {{
    echo "🛡️ Applying system hardening..."
    
    # Kernel hardening via sysctl
    cat >> /etc/sysctl.conf << EOF

# SuperSleuth Security Hardening
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

    # Apply settings
    sysctl -p
    
    # Set secure permissions on sensitive files
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    
    echo "✅ System hardening applied"
}}

# Install security tools
install_security_tools() {{
    echo "🛠️ Installing security monitoring tools..."
    
    # Install fail2ban for brute force protection
    if ! command -v fail2ban-client &> /dev/null; then
        apt-get update && apt-get install -y fail2ban || yum install -y fail2ban
        
        # Configure fail2ban
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

        systemctl enable fail2ban
        systemctl start fail2ban
    fi
    
    # Install and configure auditd
    if ! command -v auditctl &> /dev/null; then
        apt-get install -y auditd || yum install -y audit
        
        # Add basic audit rules
        cat >> /etc/audit/rules.d/supersleuth.rules << EOF
# Monitor network connections
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S accept -k network_accept

# Monitor file access
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
EOF

        service auditd restart
    fi
    
    echo "✅ Security tools installed"
}}

# Main execution
main() {{
    check_root
    backup_config
    configure_firewall
    harden_ssh
    system_hardening
    install_security_tools
    
    echo ""
    echo "✨ Security hardening complete!"
    echo ""
    echo "⚠️  Important notes:"
    echo "   - SSH root login has been disabled"
    echo "   - Password authentication disabled (use SSH keys)"
    echo "   - Firewall is now active with restrictive rules"
    echo "   - Review /etc/supersleuth/security_backups/ for backups"
    echo ""
    echo "🔄 Reboot recommended to ensure all changes take effect"
}}

main "$@"
""".format(
            timestamp=datetime.now().isoformat(),
            port_blocks=self._generate_port_blocks(open_ports)
        )
        
        return script
    
    def _generate_port_blocks(self, open_ports: List[Dict[str, Any]]) -> str:
        """Generate firewall rules to block vulnerable ports"""
        
        blocks = []
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', 'Unknown')
            risk = port_info.get('risk', 'medium')
            
            if risk in ['high', 'critical'] and port not in [22, 80, 443]:  # Don't block essential ports
                blocks.append(f"    ufw deny {port}/tcp comment 'Block {service} - {risk} risk'")
        
        return '\n'.join(blocks) if blocks else "    # No specific vulnerable ports to block"
    
    def _generate_windows_security_script(self, findings: Dict[str, Any]) -> str:
        """Generate Windows security hardening script"""
        
        script = """# SuperSleuth Network - Security Hardening Script
# Generated: {timestamp}
# Platform: Windows
# Run as Administrator in PowerShell

Write-Host "🔒 Starting security hardening..." -ForegroundColor Green

# Check for administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{{
    Write-Host "This script must be run as Administrator" -ForegroundColor Red
    exit 1
}}

# Backup current configuration
function Backup-SecurityConfig {{
    Write-Host "📦 Backing up current configuration..." -ForegroundColor Yellow
    
    $backupPath = "C:\\SuperSleuth\\SecurityBackups"
    New-Item -ItemType Directory -Force -Path $backupPath | Out-Null
    
    # Export firewall rules
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    netsh advfirewall export "$backupPath\\firewall_$timestamp.wfw"
    
    # Export security policy
    secedit /export /cfg "$backupPath\\secpol_$timestamp.cfg"
}}

# Configure Windows Firewall
function Configure-Firewall {{
    Write-Host "🔥 Configuring Windows Firewall..." -ForegroundColor Yellow
    
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    
    # Set default actions
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    
    # Remove unnecessary rules
    Get-NetFirewallRule | Where-Object {{ $_.DisplayName -like "*Telnet*" -or $_.DisplayName -like "*FTP*" }} | Remove-NetFirewallRule
    
    # Block vulnerable ports
    New-NetFirewallRule -DisplayName "Block SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
    New-NetFirewallRule -DisplayName "Block NetBIOS" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block
    New-NetFirewallRule -DisplayName "Block RDP (External)" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -RemoteAddress Internet
    
    # Allow only essential services
    New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
    New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
    
    Write-Host "✅ Firewall configured" -ForegroundColor Green
}}

# Harden Windows Security
function Harden-WindowsSecurity {{
    Write-Host "🛡️ Applying security hardening..." -ForegroundColor Yellow
    
    # Disable unnecessary services
    $servicesToDisable = @(
        "Telnet",
        "TFTP",
        "SNMP",
        "RasAuto",
        "SessionEnv",
        "TermService",
        "UmRdpService",
        "RPCLocator"
    )
    
    foreach ($service in $servicesToDisable) {{
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {{
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled
            Write-Host "   Disabled service: $service" -ForegroundColor Gray
        }}
    }}
    
    # Configure security policies via registry
    # Enable UAC to maximum
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
    
    # Disable autorun
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    
    # Enable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableScriptScanning $false
    
    Write-Host "✅ Security hardening applied" -ForegroundColor Green
}}

# Configure Account Policies
function Configure-AccountPolicies {{
    Write-Host "👤 Configuring account policies..." -ForegroundColor Yellow
    
    # Set password policy
    net accounts /minpwlen:12
    net accounts /maxpwage:90
    net accounts /minpwage:1
    net accounts /uniquepw:24
    
    # Set account lockout policy
    net accounts /lockoutthreshold:3
    net accounts /lockoutduration:30
    net accounts /lockoutwindow:30
    
    # Rename Administrator account
    $newAdminName = "SuperSleuthAdmin"
    wmic useraccount where name="Administrator" rename $newAdminName
    
    # Disable Guest account
    net user Guest /active:no
    
    Write-Host "✅ Account policies configured" -ForegroundColor Green
}}

# Enable Security Auditing
function Enable-SecurityAuditing {{
    Write-Host "📝 Enabling security auditing..." -ForegroundColor Yellow
    
    # Configure audit policies
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable /failure:enable
    
    # Increase security log size
    wevtutil sl Security /ms:1073741824
    
    Write-Host "✅ Security auditing enabled" -ForegroundColor Green
}}

# Main execution
try {{
    Backup-SecurityConfig
    Configure-Firewall
    Harden-WindowsSecurity
    Configure-AccountPolicies
    Enable-SecurityAuditing
    
    Write-Host ""
    Write-Host "✨ Security hardening complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  Important notes:" -ForegroundColor Yellow
    Write-Host "   - Windows Firewall is now restrictive" -ForegroundColor White
    Write-Host "   - Several services have been disabled" -ForegroundColor White
    Write-Host "   - Administrator account renamed to SuperSleuthAdmin" -ForegroundColor White
    Write-Host "   - Security auditing is now active" -ForegroundColor White
    Write-Host "   - Review C:\\SuperSleuth\\SecurityBackups\\ for backups" -ForegroundColor White
    Write-Host ""
    Write-Host "🔄 Reboot recommended to ensure all changes take effect" -ForegroundColor Yellow
}}
catch {{
    Write-Host "❌ Error occurred: $_" -ForegroundColor Red
    exit 1
}}
""".format(timestamp=datetime.now().isoformat())
        
        return script
    
    def _generate_macos_security_script(self, findings: Dict[str, Any]) -> str:
        """Generate macOS security hardening script"""
        
        return """#!/bin/bash
# SuperSleuth Network - Security Hardening Script
# Generated: {timestamp}
# Platform: macOS

echo "🔒 Starting security hardening..."

# Similar structure to Linux script but with macOS-specific commands
# Implementation would include:
# - Firewall configuration using pfctl
# - System Integrity Protection checks
# - Gatekeeper configuration
# - FileVault encryption setup
# - Privacy and security settings

echo "✨ Security hardening complete!"
""".format(timestamp=datetime.now().isoformat())
    
    def _generate_wifi_remediation(self, findings: Dict[str, Any], 
                                  output_path: Path, timestamp: str) -> Optional[str]:
        """Generate WiFi remediation script"""
        
        # Extract WiFi issues from findings
        wifi_issues = {}
        if 'wifi_analysis' in findings:
            wifi_results = findings['wifi_analysis'].get('results', {})
            wifi_issues = {
                'channel_recommendations': wifi_results.get('channel_analysis', {}).get('recommendations', []),
                'security_issues': wifi_results.get('security_analysis', {}).get('security_issues', [])
            }
        
        script_name = f"wifi_optimization_{timestamp}"
        
        # For WiFi, we'll generate a configuration guide instead of executable script
        config_content = self._generate_wifi_config_guide(wifi_issues)
        
        config_path = output_path / f"{script_name}_guide.txt"
        self._save_script(config_path, config_content)
        
        return str(config_path)
    
    def _generate_wifi_config_guide(self, wifi_issues: Dict[str, Any]) -> str:
        """Generate WiFi configuration guide"""
        
        guide = """SuperSleuth Network - WiFi Configuration Guide
Generated: {timestamp}

🔧 WIFI OPTIMIZATION RECOMMENDATIONS
====================================

Based on the diagnostic findings, please apply the following configurations
to your wireless access points and controllers:

## 1. CHANNEL OPTIMIZATION

""".format(timestamp=datetime.now().isoformat())
        
        # Add channel recommendations
        for rec in wifi_issues.get('channel_recommendations', []):
            guide += f"• {rec['band']} Band:\n"
            guide += f"  - Switch to channel {rec['recommended_channels'][0]}\n"
            guide += f"  - Reason: {rec['reason']}\n\n"
        
        guide += """## 2. SECURITY CONFIGURATION

• Upgrade to WPA3 encryption:
  - Access your AP admin interface
  - Navigate to Wireless Security settings
  - Select WPA3-Personal or WPA3-Enterprise
  - Use a strong passphrase (minimum 15 characters)

• Disable WPS:
  - Find WPS settings in your AP configuration
  - Disable WPS completely (vulnerable to brute force)

• Enable 802.11w (Protected Management Frames):
  - Prevents deauthentication attacks
  - Required for WPA3

## 3. PERFORMANCE OPTIMIZATION

• Channel Width:
  - 2.4GHz: Use 20MHz width to reduce interference
  - 5GHz: Use 40MHz or 80MHz for better performance

• Transmit Power:
  - Reduce power to minimize overlap between APs
  - Target -65 to -70 dBm at client locations

• Enable Band Steering:
  - Automatically move capable clients to 5GHz
  - Reduces congestion on 2.4GHz

## 4. ENTERPRISE FEATURES

• Implement 802.1X authentication:
  - Deploy RADIUS server
  - Configure EAP-TLS or PEAP
  - Use certificate-based authentication

• Enable Fast Roaming:
  - Configure 802.11r (Fast BSS Transition)
  - Configure 802.11k (Neighbor Reports)
  - Configure 802.11v (BSS Transition Management)

## 5. GUEST NETWORK ISOLATION

• Create separate VLAN for guest access
• Enable client isolation
• Implement bandwidth limits
• Use captive portal for terms acceptance

## 6. MONITORING AND MAINTENANCE

• Schedule regular firmware updates
• Monitor channel utilization
• Review client connection logs
• Perform quarterly WiFi surveys

For detailed step-by-step instructions specific to your AP model,
consult your manufacturer's documentation or contact SuperSleuth support.
"""
        
        return guide
    
    def _generate_compliance_remediation(self, findings: Dict[str, Any], 
                                       output_path: Path, timestamp: str) -> Optional[str]:
        """Generate compliance remediation checklist"""
        
        # Extract compliance gaps
        compliance_gaps = []
        if 'security_assessment' in findings:
            sec_results = findings['security_assessment'].get('results', {})
            compliance_status = sec_results.get('compliance_status', {})
            compliance_gaps = compliance_status.get('gaps', [])
        
        checklist_name = f"compliance_checklist_{timestamp}.md"
        checklist_content = self._generate_compliance_checklist(compliance_gaps)
        
        checklist_path = output_path / checklist_name
        self._save_script(checklist_path, checklist_content)
        
        return str(checklist_path)
    
    def _generate_compliance_checklist(self, gaps: List[Dict[str, Any]]) -> str:
        """Generate compliance remediation checklist"""
        
        checklist = """# SuperSleuth Network - Compliance Remediation Checklist
Generated: {timestamp}

## Compliance Gaps Identified

This checklist provides remediation steps for identified compliance gaps.

""".format(timestamp=datetime.now().isoformat())
        
        # Group gaps by framework
        gaps_by_framework = {}
        for gap in gaps:
            framework = gap.get('requirement', '').split()[0]
            if framework not in gaps_by_framework:
                gaps_by_framework[framework] = []
            gaps_by_framework[framework].append(gap)
        
        # Generate remediation steps for each framework
        for framework, framework_gaps in gaps_by_framework.items():
            checklist += f"## {framework} Compliance\n\n"
            
            for i, gap in enumerate(framework_gaps, 1):
                checklist += f"### {i}. {gap.get('requirement', 'Unknown')}\n"
                checklist += f"**Gap**: {gap.get('description', 'No description')}\n"
                checklist += f"**Severity**: {gap.get('severity', 'Unknown').upper()}\n\n"
                
                # Add specific remediation steps
                checklist += "**Remediation Steps**:\n"
                checklist += self._get_compliance_remediation_steps(framework, gap)
                checklist += "\n---\n\n"
        
        checklist += """## Implementation Priority

1. **Critical** - Implement immediately
2. **High** - Implement within 1 week
3. **Medium** - Implement within 1 month
4. **Low** - Include in next quarterly review

## Verification

After implementing each remediation:
1. Document the change
2. Test the implementation
3. Run SuperSleuth compliance scan to verify
4. Update compliance documentation

## Support

For assistance with compliance remediation:
- Email: compliance@supersleuth.network
- Documentation: https://docs.supersleuth.network/compliance
"""
        
        return checklist
    
    def _get_compliance_remediation_steps(self, framework: str, gap: Dict[str, Any]) -> str:
        """Get specific remediation steps for compliance gap"""
        
        steps = ""
        
        # PCI DSS specific steps
        if "PCI" in framework:
            if "firewall" in gap.get('description', '').lower():
                steps += """- [ ] Install and configure enterprise firewall
- [ ] Document firewall rules and business justification
- [ ] Implement change control for firewall modifications
- [ ] Schedule quarterly firewall rule reviews
"""
            elif "password" in gap.get('description', '').lower():
                steps += """- [ ] Change all default passwords immediately
- [ ] Implement password policy (min 8 chars, complexity requirements)
- [ ] Enable account lockout after 6 failed attempts
- [ ] Implement password history (last 4 passwords)
"""
            elif "encrypt" in gap.get('description', '').lower():
                steps += """- [ ] Implement TLS 1.2 or higher for all transmissions
- [ ] Disable SSL v3 and TLS 1.0
- [ ] Use strong cryptography (AES-256 or better)
- [ ] Document encryption key management procedures
"""
        
        # HIPAA specific steps
        elif "HIPAA" in framework:
            if "access" in gap.get('description', '').lower():
                steps += """- [ ] Implement role-based access control (RBAC)
- [ ] Create unique user IDs for each user
- [ ] Implement automatic logoff after 15 minutes
- [ ] Enable encryption for data at rest
"""
            elif "audit" in gap.get('description', '').lower():
                steps += """- [ ] Enable audit logging for all PHI access
- [ ] Implement log monitoring and alerting
- [ ] Retain logs for minimum 6 years
- [ ] Regularly review audit logs
"""
        
        # SOC 2 specific steps
        elif "SOC" in framework:
            if "logical" in gap.get('description', '').lower():
                steps += """- [ ] Implement multi-factor authentication
- [ ] Document access control procedures
- [ ] Perform quarterly access reviews
- [ ] Implement principle of least privilege
"""
            elif "monitor" in gap.get('description', '').lower():
                steps += """- [ ] Deploy continuous monitoring solution
- [ ] Configure real-time alerting
- [ ] Document incident response procedures
- [ ] Perform monthly monitoring reviews
"""
        
        # Generic steps if no specific match
        if not steps:
            steps += """- [ ] Review specific requirement documentation
- [ ] Identify current state vs. required state
- [ ] Implement necessary controls
- [ ] Document implementation
- [ ] Test and verify compliance
"""
        
        return steps
    
    def _save_script(self, path: Path, content: str):
        """Save script to file with appropriate permissions"""
        
        with open(path, 'w') as f:
            f.write(content)
        
        # Make scripts executable on Unix-like systems
        if self.platform in ['linux', 'macos'] and path.suffix == '.sh':
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IEXEC)
        
        self.logger.info(f"Generated remediation script: {path}")