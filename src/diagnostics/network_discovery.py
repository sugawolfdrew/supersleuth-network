"""
Network discovery and asset management module
"""

import subprocess
import json
import ipaddress
import platform
from typing import Dict, List, Optional, Any
from datetime import datetime
import socket
import struct
import os

from ..core.diagnostic import BaseDiagnostic, DiagnosticResult
from ..core.authorization import AuthorizationRequest, RiskLevel
from ..utils.logger import get_logger


class NetworkDiscovery(BaseDiagnostic):
    """Discovers devices and maps network topology"""
    
    def __init__(self, config: Dict, authorized_subnets: List[str]):
        super().__init__(config)
        self.authorized_subnets = authorized_subnets
        self.discovered_devices = []
        self.network_map = {}
        
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        
        # Check for required tools
        required_tools = ['nmap', 'arp']
        
        for tool in required_tools:
            if not self._check_tool_available(tool):
                self.logger.warning(f"Required tool '{tool}' not available")
                return False
        
        # Validate subnets
        for subnet in self.authorized_subnets:
            try:
                ipaddress.ip_network(subnet)
            except ValueError:
                self.logger.error(f"Invalid subnet: {subnet}")
                return False
        
        return True
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'network_metadata_only',
            'risk_level': RiskLevel.LOW.value,
            'requires_approval': True
        }
    
    def _run_diagnostic(self, result: DiagnosticResult):
        """Execute network discovery diagnostic"""
        
        try:
            self.logger.info("Starting network discovery scan")
            
            # Discover devices on each authorized subnet
            for subnet in self.authorized_subnets:
                self.logger.info(f"Scanning subnet: {subnet}")
                devices = self._scan_subnet(subnet)
                self.discovered_devices.extend(devices)
            
            # Build network map
            self.network_map = self._build_network_map(self.discovered_devices)
            
            # Analyze findings
            analysis = self._analyze_network(self.discovered_devices)
            
            # Complete result
            result.complete({
                'total_devices': len(self.discovered_devices),
                'devices': self.discovered_devices,
                'network_map': self.network_map,
                'analysis': analysis
            })
            
            # Add recommendations
            self._add_recommendations(result, analysis)
            
        except Exception as e:
            self.logger.error(f"Network discovery failed: {str(e)}")
            result.fail(str(e))
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            if platform.system() == "Windows":
                subprocess.run(['where', tool], capture_output=True, check=True)
            else:
                subprocess.run(['which', tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _scan_subnet(self, subnet: str) -> List[Dict[str, Any]]:
        """Scan a subnet for devices"""
        
        devices = []
        
        # Use nmap for comprehensive scanning
        if self._check_tool_available('nmap'):
            devices.extend(self._nmap_scan(subnet))
        
        # Use ARP for local network scanning
        if platform.system() != "Windows":
            devices.extend(self._arp_scan(subnet))
        
        # Deduplicate devices by MAC address
        unique_devices = {}
        for device in devices:
            mac = device.get('mac_address', device.get('ip_address'))
            if mac not in unique_devices:
                unique_devices[mac] = device
            else:
                # Merge information
                unique_devices[mac].update(device)
        
        return list(unique_devices.values())
    
    def _nmap_scan(self, subnet: str) -> List[Dict[str, Any]]:
        """Perform nmap scan on subnet"""
        
        devices = []
        
        try:
            # Run nmap with OS detection (requires elevated privileges)
            cmd = ['nmap', '-sn', subnet, '--system-dns']
            
            # Add OS detection if running with elevated privileges
            if os.geteuid() == 0 if platform.system() != "Windows" else True:
                cmd.extend(['-O', '--osscan-guess'])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                devices = self._parse_nmap_output(result.stdout)
            else:
                self.logger.warning(f"Nmap scan failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Error running nmap: {str(e)}")
        
        return devices
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output to extract device information"""
        
        devices = []
        current_device = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # New host found
            if line.startswith("Nmap scan report for"):
                if current_device:
                    devices.append(current_device)
                
                # Extract hostname and IP
                parts = line.split()
                if len(parts) >= 5:
                    hostname = parts[4]
                    if '(' in line and ')' in line:
                        ip = line[line.find('(')+1:line.find(')')]
                    else:
                        ip = hostname
                        hostname = None
                    
                    current_device = {
                        'ip_address': ip,
                        'hostname': hostname,
                        'discovered_at': datetime.now().isoformat(),
                        'discovery_method': 'nmap'
                    }
            
            # MAC address
            elif "MAC Address:" in line and current_device:
                parts = line.split()
                mac_index = parts.index("Address:") + 1
                if mac_index < len(parts):
                    current_device['mac_address'] = parts[mac_index]
                    # Vendor information might follow
                    if mac_index + 1 < len(parts) and parts[mac_index + 1].startswith('('):
                        vendor = ' '.join(parts[mac_index + 1:]).strip('()')
                        current_device['vendor'] = vendor
            
            # OS detection
            elif "OS details:" in line and current_device:
                os_details = line.split("OS details:")[1].strip()
                current_device['os_details'] = os_details
        
        # Don't forget the last device
        if current_device:
            devices.append(current_device)
        
        return devices
    
    def _arp_scan(self, subnet: str) -> List[Dict[str, Any]]:
        """Perform ARP scan on local subnet"""
        
        devices = []
        
        try:
            # Run arp command
            if platform.system() == "Darwin":  # macOS
                cmd = ['arp', '-a']
            else:  # Linux
                cmd = ['arp', '-n']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                devices = self._parse_arp_output(result.stdout, subnet)
            
        except Exception as e:
            self.logger.error(f"Error running arp: {str(e)}")
        
        return devices
    
    def _parse_arp_output(self, output: str, subnet: str) -> List[Dict[str, Any]]:
        """Parse ARP output to extract device information"""
        
        devices = []
        subnet_obj = ipaddress.ip_network(subnet)
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            # Parse based on platform
            if platform.system() == "Darwin":  # macOS
                # Format: hostname (ip) at mac [ifscope en0] on en0
                if ' at ' in line and '(' in line and ')' in line:
                    try:
                        ip = line[line.find('(')+1:line.find(')')]
                        mac_start = line.find(' at ') + 4
                        mac_end = line.find(' ', mac_start)
                        mac = line[mac_start:mac_end]
                        
                        # Check if IP is in authorized subnet
                        if ipaddress.ip_address(ip) in subnet_obj:
                            devices.append({
                                'ip_address': ip,
                                'mac_address': mac,
                                'discovered_at': datetime.now().isoformat(),
                                'discovery_method': 'arp'
                            })
                    except:
                        continue
            
            else:  # Linux
                # Format: ip (mac) [ether] on interface
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        ip = parts[0]
                        mac = parts[2] if parts[1] == 'ether' else parts[1]
                        
                        # Check if IP is in authorized subnet
                        if ipaddress.ip_address(ip) in subnet_obj:
                            devices.append({
                                'ip_address': ip,
                                'mac_address': mac,
                                'discovered_at': datetime.now().isoformat(),
                                'discovery_method': 'arp'
                            })
                    except:
                        continue
        
        return devices
    
    def _build_network_map(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a network topology map from discovered devices"""
        
        network_map = {
            'subnets': {},
            'total_devices': len(devices),
            'device_types': {},
            'vendors': {}
        }
        
        # Group devices by subnet
        for device in devices:
            ip = device['ip_address']
            
            # Find which subnet this device belongs to
            for subnet in self.authorized_subnets:
                subnet_obj = ipaddress.ip_network(subnet)
                if ipaddress.ip_address(ip) in subnet_obj:
                    subnet_key = str(subnet)
                    if subnet_key not in network_map['subnets']:
                        network_map['subnets'][subnet_key] = {
                            'devices': [],
                            'device_count': 0,
                            'utilization': 0.0
                        }
                    
                    network_map['subnets'][subnet_key]['devices'].append(device)
                    network_map['subnets'][subnet_key]['device_count'] += 1
                    
                    # Calculate subnet utilization
                    total_hosts = subnet_obj.num_addresses - 2  # Exclude network and broadcast
                    utilization = (network_map['subnets'][subnet_key]['device_count'] / total_hosts) * 100
                    network_map['subnets'][subnet_key]['utilization'] = round(utilization, 2)
                    
                    break
        
        # Count device types and vendors
        for device in devices:
            # Device type detection (simplified)
            device_type = self._detect_device_type(device)
            if device_type not in network_map['device_types']:
                network_map['device_types'][device_type] = 0
            network_map['device_types'][device_type] += 1
            
            # Vendor counting
            vendor = device.get('vendor', 'Unknown')
            if vendor not in network_map['vendors']:
                network_map['vendors'][vendor] = 0
            network_map['vendors'][vendor] += 1
        
        return network_map
    
    def _detect_device_type(self, device: Dict[str, Any]) -> str:
        """Detect device type based on available information"""
        
        # Check OS details
        os_details = device.get('os_details', '').lower()
        hostname = device.get('hostname', '').lower()
        vendor = device.get('vendor', '').lower()
        
        # Simple heuristics for device type detection
        if 'router' in os_details or 'router' in hostname:
            return 'router'
        elif 'switch' in os_details or 'switch' in hostname:
            return 'switch'
        elif 'printer' in os_details or 'printer' in hostname or 'print' in vendor:
            return 'printer'
        elif 'phone' in os_details or 'voip' in hostname:
            return 'voip_phone'
        elif 'windows' in os_details:
            return 'windows_pc'
        elif 'linux' in os_details:
            return 'linux_server'
        elif 'mac' in os_details or 'apple' in vendor:
            return 'mac_device'
        elif 'android' in os_details or 'iphone' in os_details:
            return 'mobile_device'
        elif any(iot in vendor for iot in ['sonos', 'nest', 'ring', 'alexa']):
            return 'iot_device'
        else:
            return 'unknown'
    
    def _analyze_network(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze discovered network for issues and insights"""
        
        analysis = {
            'total_devices': len(devices),
            'unknown_devices': [],
            'potential_issues': [],
            'security_concerns': [],
            'recommendations': []
        }
        
        # Identify unknown devices
        for device in devices:
            if not device.get('hostname') and device.get('vendor') == 'Unknown':
                analysis['unknown_devices'].append(device['ip_address'])
        
        # Check for security concerns
        if len(analysis['unknown_devices']) > 0:
            analysis['security_concerns'].append({
                'type': 'unknown_devices',
                'severity': 'medium',
                'description': f"Found {len(analysis['unknown_devices'])} unidentified devices",
                'devices': analysis['unknown_devices']
            })
        
        # Check for IoT devices (potential security risk)
        iot_count = sum(1 for d in devices if self._detect_device_type(d) == 'iot_device')
        if iot_count > 0:
            analysis['security_concerns'].append({
                'type': 'iot_devices',
                'severity': 'low',
                'description': f"Found {iot_count} IoT devices which may have security vulnerabilities"
            })
        
        # Check subnet utilization
        for subnet_info in self.network_map['subnets'].values():
            if subnet_info['utilization'] > 80:
                analysis['potential_issues'].append({
                    'type': 'high_subnet_utilization',
                    'severity': 'medium',
                    'description': f"Subnet utilization at {subnet_info['utilization']}%"
                })
        
        return analysis
    
    def _add_recommendations(self, result: DiagnosticResult, analysis: Dict[str, Any]):
        """Add recommendations based on analysis"""
        
        # Unknown devices
        if analysis['unknown_devices']:
            result.add_recommendation(
                f"Investigate {len(analysis['unknown_devices'])} unknown devices: "
                f"{', '.join(analysis['unknown_devices'][:3])}{'...' if len(analysis['unknown_devices']) > 3 else ''}"
            )
        
        # IoT security
        iot_count = sum(1 for d in self.discovered_devices if self._detect_device_type(d) == 'iot_device')
        if iot_count > 0:
            result.add_recommendation(
                "Implement network segmentation for IoT devices to improve security"
            )
        
        # High utilization
        for issue in analysis['potential_issues']:
            if issue['type'] == 'high_subnet_utilization':
                result.add_recommendation(
                    "Consider expanding subnet or implementing VLANs due to high utilization"
                )
                break
        
        # General security
        if len(self.discovered_devices) > 50:
            result.add_recommendation(
                "Implement network access control (NAC) to manage device connections"
            )