"""
Enterprise security assessment and vulnerability management module
"""

import subprocess
import json
import re
import socket
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import platform
import ipaddress

from ..core.diagnostic import BaseDiagnostic, DiagnosticResult
from ..core.authorization import AuthorizationRequest, RiskLevel
from ..utils.logger import get_logger


class SecurityAssessment(BaseDiagnostic):
    """Enterprise-grade network security assessment"""
    
    def __init__(self, config: Dict, compliance_frameworks: List[str]):
        super().__init__(config)
        self.compliance_frameworks = compliance_frameworks
        self.scan_depth = config.get('scan_depth', 'moderate')  # light, moderate, deep
        self.include_vulnerability_scan = config.get('vulnerability_scan', True)
        self.check_configurations = config.get('check_configurations', True)
        
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        
        # Check for security scanning tools
        required_tools = []
        optional_tools = ['nmap']
        
        # Check optional tools and log their availability
        self.available_tools = {}
        for tool in optional_tools:
            self.available_tools[tool] = self._check_tool_available(tool)
            if self.available_tools[tool]:
                self.logger.info(f"Security tool '{tool}' is available")
            else:
                self.logger.warning(f"Security tool '{tool}' not available - some checks will be limited")
        
        return True  # Can proceed with basic checks even without advanced tools
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        
        risk_level = RiskLevel.MEDIUM
        if self.scan_depth == 'deep':
            risk_level = RiskLevel.HIGH
        
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'security_configuration_metadata',
            'risk_level': risk_level.value,
            'requires_approval': True,
            'business_impact': 'Security scanning may trigger IDS/IPS alerts',
            'compliance_note': f'Assessment for: {", ".join(self.compliance_frameworks)}'
        }
    
    def _run_diagnostic(self, result: DiagnosticResult):
        """Execute security assessment diagnostic"
        
        try:
            self.logger.info(f"Starting security assessment for compliance: {', '.join(self.compliance_frameworks)}")
            
            # Network security assessment
            network_security = self._assess_network_security()
            
            # WiFi security assessment
            wifi_security = self._assess_wifi_security()
            
            # Access control assessment
            access_control = self._assess_access_control()
            
            # Vulnerability scanning (if authorized)
            vulnerabilities = self._scan_vulnerabilities() if self.include_vulnerability_scan else None
            
            # Configuration assessment
            config_assessment = self._assess_configurations() if self.check_configurations else None
            
            # Compliance validation
            compliance_results = self._validate_compliance(
                network_security, wifi_security, access_control, 
                vulnerabilities, config_assessment
            )
            
            # Rogue device detection
            rogue_devices = self._detect_rogue_devices()
            
            # Complete result
            result.complete({
                'assessment_timestamp': datetime.now().isoformat(),
                'compliance_frameworks': self.compliance_frameworks,
                'network_security': network_security,
                'wifi_security': wifi_security,
                'access_control': access_control,
                'vulnerabilities': vulnerabilities,
                'configuration': config_assessment,
                'rogue_devices': rogue_devices,
                'compliance_status': compliance_results,
                'overall_risk_score': self._calculate_risk_score(
                    network_security, wifi_security, vulnerabilities, rogue_devices
                )
            })
            
            # Add recommendations
            self._add_security_recommendations(
                result, network_security, wifi_security, 
                vulnerabilities, compliance_results
            )
            
        except Exception as e:
            self.logger.error(f"Security assessment failed: {str(e)}")
            result.fail(str(e))
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _assess_network_security(self) -> Dict[str, Any]:
        """Assess general network security"""
        
        self.logger.info("Assessing network security...")
        
        assessment = {
            'open_ports': [],
            'services': [],
            'firewall_status': self._check_firewall_status(),
            'network_segmentation': self._check_network_segmentation(),
            'encryption_protocols': self._check_encryption_protocols(),
            'security_issues': []
        }
        
        # Check for common vulnerable ports
        vulnerable_ports = {
            23: 'Telnet (unencrypted)',
            21: 'FTP (unencrypted)',
            139: 'NetBIOS',
            445: 'SMB',
            3389: 'RDP',
            1433: 'SQL Server',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB'
        }
        
        # Quick port scan on localhost
        for port, service in vulnerable_ports.items():
            if self._is_port_open('127.0.0.1', port):
                assessment['open_ports'].append({
                    'port': port,
                    'service': service,
                    'risk': 'high' if port in [23, 21, 139] else 'medium'
                })
                assessment['security_issues'].append({
                    'type': 'open_vulnerable_port',
                    'severity': 'high' if port in [23, 21] else 'medium',
                    'port': port,
                    'service': service,
                    'message': f'Port {port} ({service}) is open and may pose security risk'
                })
        
        # Check for HTTPS enforcement
        https_check = self._check_https_enforcement()
        if not https_check['enforced']:
            assessment['security_issues'].append({
                'type': 'no_https_enforcement',
                'severity': 'medium',
                'message': 'HTTPS is not enforced for all web services'
            })
        
        assessment['https_enforcement'] = https_check
        
        return assessment
    
    def _assess_wifi_security(self) -> Dict[str, Any]:
        """Assess WiFi-specific security"""
        
        self.logger.info("Assessing WiFi security...")
        
        # This would integrate with the WiFi analysis module
        # For now, return a basic assessment
        
        assessment = {
            'encryption_methods': [],
            'authentication_methods': [],
            'wps_enabled': self._check_wps_status(),
            'hidden_ssid': False,
            'mac_filtering': False,
            'security_issues': []
        }
        
        # Check for WPS vulnerability
        if assessment['wps_enabled']:
            assessment['security_issues'].append({
                'type': 'wps_enabled',
                'severity': 'high',
                'message': 'WPS is vulnerable to brute force attacks'
            })
        
        return assessment
    
    def _assess_access_control(self) -> Dict[str, Any]:
        """Assess network access control"""
        
        self.logger.info("Assessing access control...")
        
        assessment = {
            'authentication_methods': [],
            'authorization_policies': [],
            'privileged_access': self._check_privileged_access(),
            'default_credentials': self._check_default_credentials(),
            'security_issues': []
        }
        
        # Check for default credentials
        if assessment['default_credentials']['found']:
            assessment['security_issues'].append({
                'type': 'default_credentials',
                'severity': 'critical',
                'devices': assessment['default_credentials']['devices'],
                'message': 'Default credentials detected on network devices'
            })
        
        # Check for weak authentication
        weak_auth_methods = ['password-only', 'no-auth']
        for method in assessment['authentication_methods']:
            if method in weak_auth_methods:
                assessment['security_issues'].append({
                    'type': 'weak_authentication',
                    'severity': 'high',
                    'method': method,
                    'message': f'Weak authentication method in use: {method}'
                })
        
        return assessment
    
    def _scan_vulnerabilities(self) -> Optional[Dict[str, Any]]:
        """Perform vulnerability scanning"""
        
        if not self.available_tools.get('nmap'):
            self.logger.warning("Nmap not available - skipping vulnerability scan")
            return {
                'scan_performed': False,
                'reason': 'Required tools not available'
            }
        
        self.logger.info("Scanning for vulnerabilities...")
        
        vulnerabilities = {
            'scan_performed': True,
            'scan_depth': self.scan_depth,
            'cve_vulnerabilities': [],
            'misconfigurations': [],
            'outdated_services': [],
            'security_issues': []
        }
        
        # Perform service version detection
        try:
            # Limited scan on local network only
            cmd = ['nmap', '-sV', '--version-intensity', '5', '-p-', 'localhost']
            
            if self.scan_depth == 'deep':
                cmd.extend(['--script', 'vuln'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                vulnerabilities.update(self._parse_nmap_vulnerabilities(result.stdout))
            
        except subprocess.TimeoutExpired:
            self.logger.warning("Vulnerability scan timed out")
        except Exception as e:
            self.logger.error(f"Vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _assess_configurations(self) -> Dict[str, Any]:
        """Assess security configurations"""
        
        self.logger.info("Assessing security configurations...")
        
        config_assessment = {
            'dns_security': self._check_dns_security(),
            'ntp_security': self._check_ntp_security(),
            'logging_enabled': self._check_logging_configuration(),
            'update_status': self._check_update_status(),
            'security_issues': []
        }
        
        # Check for insecure configurations
        if not config_assessment['dns_security']['dnssec_enabled']:
            config_assessment['security_issues'].append({
                'type': 'no_dnssec',
                'severity': 'medium',
                'message': 'DNSSEC not enabled - vulnerable to DNS spoofing'
            })
        
        if not config_assessment['logging_enabled']['sufficient']:
            config_assessment['security_issues'].append({
                'type': 'insufficient_logging',
                'severity': 'medium',
                'message': 'Security logging insufficient for incident response'
            })
        
        return config_assessment
    
    def _detect_rogue_devices(self) -> Dict[str, Any]:
        """Detect potential rogue devices"""
        
        self.logger.info("Detecting rogue devices...")
        
        rogue_detection = {
            'scan_performed': True,
            'suspicious_devices': [],
            'unauthorized_services': [],
            'spoofing_indicators': []
        }
        
        # Check for suspicious MAC addresses
        suspicious_mac_prefixes = [
            '00:0C:29',  # VMware
            '00:50:56',  # VMware
            '08:00:27',  # VirtualBox
            '00:16:3E',  # Xen
        ]
        
        # This would integrate with network discovery
        # For now, return placeholder
        
        return rogue_detection
    
    def _validate_compliance(self, network_security: Dict[str, Any],
                           wifi_security: Dict[str, Any],
                           access_control: Dict[str, Any],
                           vulnerabilities: Optional[Dict[str, Any]],
                           config_assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate against compliance frameworks"""
        
        self.logger.info(f"Validating compliance for: {', '.join(self.compliance_frameworks)}")
        
        compliance_results = {
            'overall_compliant': True,
            'framework_results': {},
            'gaps': [],
            'remediation_required': []
        }
        
        for framework in self.compliance_frameworks:
            if framework == 'PCI_DSS':
                result = self._validate_pci_dss(network_security, wifi_security, access_control)
            elif framework == 'HIPAA':
                result = self._validate_hipaa(network_security, access_control, config_assessment)
            elif framework == 'SOC2':
                result = self._validate_soc2(access_control, config_assessment)
            elif framework == 'ISO27001':
                result = self._validate_iso27001(network_security, access_control, config_assessment)
            else:
                result = {'compliant': True, 'gaps': []}
            
            compliance_results['framework_results'][framework] = result
            
            if not result['compliant']:
                compliance_results['overall_compliant'] = False
                compliance_results['gaps'].extend(result['gaps'])
        
        return compliance_results
    
    def _validate_pci_dss(self, network_security: Dict[str, Any],
                         wifi_security: Dict[str, Any],
                         access_control: Dict[str, Any]) -> Dict[str, Any]:
        """Validate PCI DSS compliance"""
        
        validation = {
            'compliant': True,
            'gaps': [],
            'requirements_checked': []
        }
        
        # Requirement 1: Firewall configuration
        if not network_security.get('firewall_status', {}).get('enabled'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'PCI DSS 1.1',
                'description': 'Firewall must be installed and maintained',
                'severity': 'critical'
            })
        
        # Requirement 2: Default passwords
        if access_control.get('default_credentials', {}).get('found'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'PCI DSS 2.1',
                'description': 'Default passwords must be changed',
                'severity': 'critical'
            })
        
        # Requirement 4: Encryption
        open_ports = network_security.get('open_ports', [])
        unencrypted_services = [p for p in open_ports if p['port'] in [21, 23, 80]]
        if unencrypted_services:
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'PCI DSS 4.1',
                'description': 'Sensitive data must be encrypted in transit',
                'severity': 'high',
                'services': unencrypted_services
            })
        
        return validation
    
    def _validate_hipaa(self, network_security: Dict[str, Any],
                       access_control: Dict[str, Any],
                       config_assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate HIPAA compliance"""
        
        validation = {
            'compliant': True,
            'gaps': [],
            'requirements_checked': []
        }
        
        # Access controls
        if not access_control.get('authentication_methods'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'HIPAA 164.312(a)(1)',
                'description': 'Access control mechanisms required',
                'severity': 'high'
            })
        
        # Audit logs
        if config_assessment and not config_assessment.get('logging_enabled', {}).get('sufficient'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'HIPAA 164.312(b)',
                'description': 'Audit logs must be maintained',
                'severity': 'high'
            })
        
        # Encryption
        if network_security.get('encryption_protocols', {}).get('weak_protocols'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'HIPAA 164.312(e)(1)',
                'description': 'PHI must be encrypted in transit',
                'severity': 'critical'
            })
        
        return validation
    
    def _validate_soc2(self, access_control: Dict[str, Any],
                      config_assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate SOC 2 compliance"""
        
        validation = {
            'compliant': True,
            'gaps': [],
            'requirements_checked': []
        }
        
        # Logical access controls
        if access_control.get('privileged_access', {}).get('unrestricted'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'SOC 2 CC6.1',
                'description': 'Logical access controls must be implemented',
                'severity': 'high'
            })
        
        # System monitoring
        if config_assessment and not config_assessment.get('logging_enabled', {}).get('sufficient'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'SOC 2 CC7.1',
                'description': 'System monitoring must be implemented',
                'severity': 'medium'
            })
        
        return validation
    
    def _validate_iso27001(self, network_security: Dict[str, Any],
                          access_control: Dict[str, Any],
                          config_assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate ISO 27001 compliance"""
        
        validation = {
            'compliant': True,
            'gaps': [],
            'requirements_checked': []
        }
        
        # A.13.1.1 Network controls
        if not network_security.get('network_segmentation', {}).get('implemented'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'ISO 27001 A.13.1.1',
                'description': 'Networks shall be managed and controlled',
                'severity': 'medium'
            })
        
        # A.9.2.1 User access management
        if access_control.get('default_credentials', {}).get('found'):
            validation['compliant'] = False
            validation['gaps'].append({
                'requirement': 'ISO 27001 A.9.2.1',
                'description': 'User access must be properly managed',
                'severity': 'high'
            })
        
        return validation
    
    def _check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall status"""
        
        system = platform.system()
        
        try:
            if system == "Linux":
                # Check iptables
                cmd = ['sudo', 'iptables', '-L', '-n']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    rules_count = len(result.stdout.strip().split('\n'))
                    return {
                        'enabled': rules_count > 10,  # Basic heuristic
                        'type': 'iptables',
                        'rules_count': rules_count
                    }
            
            elif system == "Darwin":  # macOS
                # Check pfctl
                cmd = ['sudo', 'pfctl', '-s', 'info']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    return {
                        'enabled': 'Status: Enabled' in result.stdout,
                        'type': 'pf'
                    }
            
            elif system == "Windows":
                # Check Windows Firewall
                cmd = ['netsh', 'advfirewall', 'show', 'allprofiles', 'state']
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                
                if result.returncode == 0:
                    return {
                        'enabled': 'ON' in result.stdout,
                        'type': 'Windows Firewall'
                    }
        
        except Exception as e:
            self.logger.error(f"Error checking firewall: {str(e)}")
        
        return {'enabled': False, 'type': 'unknown'}
    
    def _check_network_segmentation(self) -> Dict[str, Any]:
        """Check for network segmentation"""
        
        # This would check VLANs, subnets, etc.
        # For now, return basic check
        
        try:
            # Get network interfaces
            import netifaces
            
            interfaces = netifaces.interfaces()
            networks = set()
            
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        if ip and netmask and not ip.startswith('127.'):
                            # Calculate network
                            network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                            networks.add(str(network))
            
            return {
                'implemented': len(networks) > 1,
                'segments_found': len(networks),
                'networks': list(networks)
            }
        
        except Exception as e:
            self.logger.error(f"Error checking network segmentation: {str(e)}")
            return {'implemented': False, 'segments_found': 0}
    
    def _check_encryption_protocols(self) -> Dict[str, Any]:
        """Check encryption protocols in use"""
        
        protocols = {
            'strong_protocols': [],
            'weak_protocols': [],
            'deprecated_protocols': []
        }
        
        # Check SSL/TLS versions (simplified)
        # In production, would scan actual services
        
        return protocols
    
    def _is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open"""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _check_https_enforcement(self) -> Dict[str, Any]:
        """Check HTTPS enforcement"""
        
        # Check if HTTP port 80 is open
        http_open = self._is_port_open('127.0.0.1', 80)
        https_open = self._is_port_open('127.0.0.1', 443)
        
        return {
            'enforced': not http_open and https_open,
            'http_open': http_open,
            'https_open': https_open
        }
    
    def _check_wps_status(self) -> bool:
        """Check if WPS is enabled"""
        
        # This would check actual AP configuration
        # For now, return False
        return False
    
    def _check_privileged_access(self) -> Dict[str, Any]:
        """Check privileged access controls"""
        
        return {
            'unrestricted': False,
            'sudo_users_count': 0,
            'root_login_enabled': False
        }
    
    def _check_default_credentials(self) -> Dict[str, Any]:
        """Check for default credentials"""
        
        # This would test common default credentials
        # For security, we don't actually attempt logins
        
        return {
            'found': False,
            'devices': []
        }
    
    def _check_dns_security(self) -> Dict[str, Any]:
        """Check DNS security configuration"""
        
        return {
            'dnssec_enabled': False,
            'dns_over_https': False,
            'dns_over_tls': False
        }
    
    def _check_ntp_security(self) -> Dict[str, Any]:
        """Check NTP security configuration"""
        
        return {
            'authenticated': False,
            'restricted_access': False
        }
    
    def _check_logging_configuration(self) -> Dict[str, Any]:
        """Check logging configuration"""
        
        # Check if common log files exist and are being written to
        log_locations = [
            '/var/log/syslog',
            '/var/log/auth.log',
            '/var/log/secure',
            'C:\\Windows\\System32\\winevt\\Logs'
        ]
        
        active_logs = 0
        for log_path in log_locations:
            try:
                if platform.system() == "Windows" and 'Windows' in log_path:
                    active_logs += 1  # Assume Windows logging is active
                else:
                    import os
                    if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
                        active_logs += 1
            except:
                pass
        
        return {
            'sufficient': active_logs >= 2,
            'active_logs': active_logs,
            'centralized_logging': False
        }
    
    def _check_update_status(self) -> Dict[str, Any]:
        """Check system update status"""
        
        return {
            'automatic_updates': False,
            'last_update': 'unknown',
            'pending_updates': 'unknown'
        }
    
    def _parse_nmap_vulnerabilities(self, output: str) -> Dict[str, Any]:
        """Parse Nmap vulnerability scan output"""
        
        vulnerabilities = {
            'services': [],
            'cve_found': []
        }
        
        # Parse for version information and CVEs
        lines = output.split('\n')
        current_port = None
        
        for line in lines:
            # Port/service line
            port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
            if port_match:
                current_port = {
                    'port': int(port_match.group(1)),
                    'service': port_match.group(2),
                    'version': port_match.group(3).strip()
                }
                vulnerabilities['services'].append(current_port)
            
            # CVE matches
            cve_match = re.findall(r'CVE-\d{4}-\d+', line)
            if cve_match:
                for cve in cve_match:
                    vulnerabilities['cve_found'].append({
                        'cve_id': cve,
                        'port': current_port['port'] if current_port else 'unknown'
                    })
        
        return vulnerabilities
    
    def _calculate_risk_score(self, network_security: Dict[str, Any],
                            wifi_security: Dict[str, Any],
                            vulnerabilities: Optional[Dict[str, Any]],
                            rogue_devices: Dict[str, Any]) -> int:
        """Calculate overall security risk score (0-100, lower is better)"""
        
        risk_score = 0
        
        # Network security risks
        for issue in network_security.get('security_issues', []):
            if issue['severity'] == 'critical':
                risk_score += 20
            elif issue['severity'] == 'high':
                risk_score += 15
            elif issue['severity'] == 'medium':
                risk_score += 10
            else:
                risk_score += 5
        
        # WiFi security risks
        for issue in wifi_security.get('security_issues', []):
            if issue['severity'] == 'critical':
                risk_score += 15
            elif issue['severity'] == 'high':
                risk_score += 10
            else:
                risk_score += 5
        
        # Vulnerability risks
        if vulnerabilities and vulnerabilities.get('cve_found'):
            risk_score += len(vulnerabilities['cve_found']) * 10
        
        # Rogue device risks
        if rogue_devices.get('suspicious_devices'):
            risk_score += len(rogue_devices['suspicious_devices']) * 15
        
        return min(100, risk_score)
    
    def _add_security_recommendations(self, result: DiagnosticResult,
                                    network_security: Dict[str, Any],
                                    wifi_security: Dict[str, Any],
                                    vulnerabilities: Optional[Dict[str, Any]],
                                    compliance_results: Dict[str, Any]):
        """Add security recommendations based on findings"""
        
        # Critical recommendations first
        critical_issues = []
        
        # Network security recommendations
        for issue in network_security.get('security_issues', []):
            if issue['severity'] in ['critical', 'high']:
                if issue['type'] == 'open_vulnerable_port':
                    result.add_recommendation(
                        f"CRITICAL: Close or secure port {issue['port']} ({issue['service']})"
                    )
                    critical_issues.append(issue)
        
        # Default credentials
        if network_security.get('default_credentials', {}).get('found'):
            result.add_recommendation(
                "CRITICAL: Change default credentials on all network devices immediately"
            )
        
        # Firewall recommendations
        if not network_security.get('firewall_status', {}).get('enabled'):
            result.add_recommendation(
                "HIGH: Enable and configure firewall to protect network perimeter"
            )
        
        # Encryption recommendations
        if not network_security.get('https_enforcement', {}).get('enforced'):
            result.add_recommendation(
                "Enforce HTTPS for all web services and disable HTTP access"
            )
        
        # WiFi security recommendations
        if wifi_security.get('wps_enabled'):
            result.add_recommendation(
                "Disable WPS on all access points - vulnerable to brute force attacks"
            )
        
        # Compliance recommendations
        if not compliance_results['overall_compliant']:
            for gap in compliance_results['gaps'][:3]:  # Top 3 gaps
                result.add_recommendation(
                    f"Compliance Gap ({gap['requirement']}): {gap['description']}"
                )
        
        # Vulnerability recommendations
        if vulnerabilities and vulnerabilities.get('cve_found'):
            result.add_recommendation(
                f"Address {len(vulnerabilities['cve_found'])} CVE vulnerabilities found in network services"
            )
        
        # General security hygiene
        if len(critical_issues) == 0:
            result.add_recommendation(
                "Implement regular security assessments and penetration testing"
            )