"""
DHCP Diagnostics Module for SuperSleuth Network

This module provides comprehensive DHCP diagnostics capabilities including:
- DHCP server discovery
- IP conflict detection
- Lease analysis
- Rogue DHCP server detection
- Lease renewal testing

Designed for use by Claude Code with minimal dependencies.
"""

import socket
import struct
import time
import random
import threading
import ipaddress
import subprocess
import re
import platform
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta

try:
    import netifaces
except ImportError:
    netifaces = None
    print("Warning: netifaces not installed. Some functionality may be limited.")


class DHCPDiagnostics:
    """Main class for DHCP diagnostic operations"""
    
    # DHCP message types
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    
    # DHCP ports
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68
    
    def __init__(self):
        self.discovered_servers = []
        self.ip_conflicts = []
        self.lease_info = {}
        
    def discover_dhcp_servers(self, interface: Optional[str] = None, timeout: int = 5) -> List[Dict[str, Any]]:
        """
        Discover available DHCP servers on the network
        
        Args:
            interface: Network interface to use (None for default)
            timeout: Discovery timeout in seconds
            
        Returns:
            List of discovered DHCP servers with their details
        """
        servers = []
        
        try:
            # Create DHCP DISCOVER packet
            discover_packet = self._create_dhcp_discover()
            
            # Create socket for DHCP communication
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                sock.bind(('', self.DHCP_CLIENT_PORT))
            except PermissionError:
                # Try alternative approach for non-root users
                sock.bind(('', 0))
            
            sock.settimeout(timeout)
            
            # Send DISCOVER packet
            sock.sendto(discover_packet, ('<broadcast>', self.DHCP_SERVER_PORT))
            
            # Wait for OFFER responses
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    server_info = self._parse_dhcp_offer(data, addr)
                    if server_info and server_info not in servers:
                        servers.append(server_info)
                except socket.timeout:
                    break
                except Exception as e:
                    continue
                    
            sock.close()
            
        except Exception as e:
            return [{
                'error': f'Failed to discover DHCP servers: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }]
            
        self.discovered_servers = servers
        return servers
    
    def detect_ip_conflicts(self, ip_address: str = None) -> List[Dict[str, Any]]:
        """
        Detect IP address conflicts on the network
        
        Args:
            ip_address: Specific IP to check (None to check current IP)
            
        Returns:
            List of detected conflicts with details
        """
        conflicts = []
        
        try:
            # Get current IP if not specified
            if not ip_address:
                ip_address = self._get_current_ip()
                if not ip_address:
                    return [{
                        'error': 'Could not determine current IP address',
                        'timestamp': datetime.now().isoformat()
                    }]
            
            # Send ARP requests to detect duplicates
            mac_addresses = self._arp_scan(ip_address)
            
            if len(mac_addresses) > 1:
                conflicts.append({
                    'ip_address': ip_address,
                    'conflicting_macs': list(mac_addresses),
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'recommendation': 'Release and renew DHCP lease or contact network administrator'
                })
            
            # Also check via ICMP
            if self._ping_host(ip_address):
                local_mac = self._get_local_mac()
                remote_mac = self._get_mac_for_ip(ip_address)
                
                if local_mac and remote_mac and local_mac != remote_mac:
                    conflicts.append({
                        'ip_address': ip_address,
                        'local_mac': local_mac,
                        'remote_mac': remote_mac,
                        'detection_method': 'ICMP',
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            return [{
                'error': f'Failed to detect IP conflicts: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }]
            
        self.ip_conflicts = conflicts
        return conflicts
    
    def analyze_dhcp_lease(self) -> Dict[str, Any]:
        """
        Analyze current DHCP lease information
        
        Returns:
            Dictionary containing lease analysis results
        """
        lease_info = {
            'current_ip': None,
            'lease_obtained': None,
            'lease_expires': None,
            'dhcp_server': None,
            'gateway': None,
            'dns_servers': [],
            'lease_time_remaining': None,
            'status': 'unknown',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                lease_info.update(self._parse_windows_lease())
            elif system in ['linux', 'darwin']:
                lease_info.update(self._parse_unix_lease())
            else:
                lease_info['error'] = f'Unsupported operating system: {system}'
                
            # Calculate remaining lease time
            if lease_info.get('lease_expires'):
                try:
                    expires = datetime.fromisoformat(lease_info['lease_expires'])
                    remaining = expires - datetime.now()
                    lease_info['lease_time_remaining'] = str(remaining)
                    
                    # Determine status
                    if remaining.total_seconds() < 0:
                        lease_info['status'] = 'expired'
                    elif remaining.total_seconds() < 3600:  # Less than 1 hour
                        lease_info['status'] = 'expiring_soon'
                    else:
                        lease_info['status'] = 'active'
                except:
                    pass
                    
        except Exception as e:
            lease_info['error'] = f'Failed to analyze DHCP lease: {str(e)}'
            
        self.lease_info = lease_info
        return lease_info
    
    def detect_rogue_dhcp_servers(self, authorized_servers: List[str] = None) -> List[Dict[str, Any]]:
        """
        Detect potential rogue DHCP servers on the network
        
        Args:
            authorized_servers: List of authorized DHCP server IPs
            
        Returns:
            List of detected rogue servers
        """
        rogue_servers = []
        
        try:
            # First discover all DHCP servers
            all_servers = self.discover_dhcp_servers(timeout=10)
            
            if not authorized_servers:
                # Try to determine authorized server from current lease
                lease_info = self.analyze_dhcp_lease()
                if lease_info.get('dhcp_server'):
                    authorized_servers = [lease_info['dhcp_server']]
                else:
                    # If no authorized list provided, flag all but the first as potential rogues
                    if len(all_servers) > 1:
                        authorized_servers = [all_servers[0]['server_ip']]
            
            # Check each discovered server
            for server in all_servers:
                if 'error' in server:
                    continue
                    
                server_ip = server.get('server_ip')
                if server_ip and authorized_servers and server_ip not in authorized_servers:
                    rogue_servers.append({
                        'server_ip': server_ip,
                        'server_id': server.get('server_id'),
                        'offered_ip': server.get('offered_ip'),
                        'severity': 'critical',
                        'detected_at': datetime.now().isoformat(),
                        'recommendation': 'Immediately report to network administrator'
                    })
                    
            # Additional check: Multiple servers offering different configurations
            if len(all_servers) > 1:
                configs = {}
                for server in all_servers:
                    if 'error' in server:
                        continue
                    config_key = (
                        server.get('subnet_mask'),
                        server.get('gateway'),
                        tuple(server.get('dns_servers', []))
                    )
                    if config_key not in configs:
                        configs[config_key] = []
                    configs[config_key].append(server['server_ip'])
                
                if len(configs) > 1:
                    rogue_servers.append({
                        'type': 'configuration_mismatch',
                        'severity': 'high',
                        'details': 'Multiple DHCP servers offering different configurations',
                        'servers': all_servers,
                        'detected_at': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            return [{
                'error': f'Failed to detect rogue DHCP servers: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }]
            
        return rogue_servers
    
    def test_lease_renewal(self) -> Dict[str, Any]:
        """
        Test DHCP lease renewal process
        
        Returns:
            Dictionary containing renewal test results
        """
        results = {
            'test_started': datetime.now().isoformat(),
            'current_lease': None,
            'renewal_attempted': False,
            'renewal_successful': False,
            'new_lease': None,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Get current lease info
            current_lease = self.analyze_dhcp_lease()
            results['current_lease'] = current_lease
            
            if current_lease.get('status') == 'expired':
                results['warnings'].append('Current lease is already expired')
            
            # Attempt renewal based on OS
            system = platform.system().lower()
            
            if system == 'windows':
                success = self._renew_windows_lease()
            elif system == 'darwin':
                success = self._renew_macos_lease()
            elif system == 'linux':
                success = self._renew_linux_lease()
            else:
                results['errors'].append(f'Unsupported operating system: {system}')
                return results
            
            results['renewal_attempted'] = True
            results['renewal_successful'] = success
            
            if success:
                # Wait a moment for renewal to complete
                time.sleep(2)
                
                # Get new lease info
                new_lease = self.analyze_dhcp_lease()
                results['new_lease'] = new_lease
                
                # Compare leases
                if current_lease.get('current_ip') != new_lease.get('current_ip'):
                    results['warnings'].append('IP address changed after renewal')
                
                if current_lease.get('dhcp_server') != new_lease.get('dhcp_server'):
                    results['warnings'].append('DHCP server changed after renewal')
            else:
                results['errors'].append('Lease renewal failed')
                
        except Exception as e:
            results['errors'].append(f'Failed to test lease renewal: {str(e)}')
            
        results['test_completed'] = datetime.now().isoformat()
        return results
    
    # Helper methods
    
    def _create_dhcp_discover(self) -> bytes:
        """Create a DHCP DISCOVER packet"""
        # Generate transaction ID
        xid = random.randint(0, 0xFFFFFFFF)
        
        # Get MAC address
        mac_addr = self._get_local_mac()
        if not mac_addr:
            mac_addr = "00:00:00:00:00:00"
        
        mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
        
        # Build DHCP DISCOVER packet
        packet = struct.pack('!B', 1)  # Message type: Boot Request
        packet += struct.pack('!B', 1)  # Hardware type: Ethernet
        packet += struct.pack('!B', 6)  # Hardware address length
        packet += struct.pack('!B', 0)  # Hops
        packet += struct.pack('!I', xid)  # Transaction ID
        packet += struct.pack('!H', 0)  # Seconds elapsed
        packet += struct.pack('!H', 0x8000)  # Flags (Broadcast)
        packet += struct.pack('!4s', b'\x00\x00\x00\x00')  # Client IP
        packet += struct.pack('!4s', b'\x00\x00\x00\x00')  # Your IP
        packet += struct.pack('!4s', b'\x00\x00\x00\x00')  # Server IP
        packet += struct.pack('!4s', b'\x00\x00\x00\x00')  # Gateway IP
        packet += mac_bytes + b'\x00' * 10  # Client MAC + padding
        packet += b'\x00' * 64  # Server host name
        packet += b'\x00' * 128  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie
        
        # DHCP options
        packet += b'\x35\x01\x01'  # DHCP Message Type: DISCOVER
        packet += b'\xff'  # End option
        
        return packet
    
    def _parse_dhcp_offer(self, data: bytes, addr: Tuple[str, int]) -> Optional[Dict[str, Any]]:
        """Parse a DHCP OFFER packet"""
        try:
            if len(data) < 240:
                return None
                
            # Check magic cookie
            if data[236:240] != b'\x63\x82\x53\x63':
                return None
            
            server_info = {
                'server_ip': addr[0],
                'offered_ip': socket.inet_ntoa(data[16:20]),
                'transaction_id': struct.unpack('!I', data[4:8])[0],
                'timestamp': datetime.now().isoformat()
            }
            
            # Parse options
            i = 240
            while i < len(data):
                if data[i] == 0xff:  # End option
                    break
                elif data[i] == 0:  # Pad option
                    i += 1
                    continue
                    
                option = data[i]
                length = data[i + 1]
                value = data[i + 2:i + 2 + length]
                
                if option == 1:  # Subnet mask
                    server_info['subnet_mask'] = socket.inet_ntoa(value)
                elif option == 3:  # Gateway
                    server_info['gateway'] = socket.inet_ntoa(value[:4])
                elif option == 6:  # DNS servers
                    dns_servers = []
                    for j in range(0, len(value), 4):
                        dns_servers.append(socket.inet_ntoa(value[j:j+4]))
                    server_info['dns_servers'] = dns_servers
                elif option == 51:  # Lease time
                    server_info['lease_time'] = struct.unpack('!I', value)[0]
                elif option == 54:  # Server identifier
                    server_info['server_id'] = socket.inet_ntoa(value)
                    
                i += 2 + length
                
            return server_info
            
        except Exception:
            return None
    
    def _get_current_ip(self) -> Optional[str]:
        """Get current IP address"""
        try:
            if netifaces:
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr['addr']
                            if ip != '127.0.0.1':
                                return ip
            else:
                # Fallback method
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
        except:
            return None
    
    def _get_local_mac(self) -> Optional[str]:
        """Get local MAC address"""
        try:
            if netifaces:
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_LINK in addrs:
                        for addr in addrs[netifaces.AF_LINK]:
                            mac = addr.get('addr')
                            if mac and mac != '00:00:00:00:00:00':
                                return mac
            else:
                # Fallback to system commands
                system = platform.system().lower()
                if system == 'windows':
                    output = subprocess.check_output('getmac', shell=True).decode()
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                    if match:
                        return match.group(0).replace('-', ':')
                else:
                    output = subprocess.check_output('ifconfig', shell=True).decode()
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                    if match:
                        return match.group(0)
        except:
            return None
    
    def _arp_scan(self, ip_address: str) -> set:
        """Perform ARP scan for an IP address"""
        mac_addresses = set()
        
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                # Send ping first to populate ARP cache
                subprocess.run(['ping', '-n', '1', '-w', '1000', ip_address], 
                             capture_output=True, check=False)
                
                # Check ARP table
                output = subprocess.check_output(['arp', '-a'], text=True)
                for line in output.split('\n'):
                    if ip_address in line:
                        match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if match:
                            mac_addresses.add(match.group(0).upper().replace('-', ':'))
            else:
                # For Unix-like systems
                subprocess.run(['ping', '-c', '1', '-W', '1', ip_address], 
                             capture_output=True, check=False)
                
                output = subprocess.check_output(['arp', '-n'], text=True)
                for line in output.split('\n'):
                    if ip_address in line:
                        match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if match:
                            mac_addresses.add(match.group(0).upper())
        except:
            pass
            
        return mac_addresses
    
    def _ping_host(self, ip_address: str) -> bool:
        """Check if host responds to ping"""
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip_address], 
                                      capture_output=True, check=False)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip_address], 
                                      capture_output=True, check=False)
                                      
            return result.returncode == 0
        except:
            return False
    
    def _get_mac_for_ip(self, ip_address: str) -> Optional[str]:
        """Get MAC address for a given IP"""
        macs = self._arp_scan(ip_address)
        return list(macs)[0] if macs else None
    
    def _parse_windows_lease(self) -> Dict[str, Any]:
        """Parse Windows DHCP lease information"""
        lease_info = {}
        
        try:
            output = subprocess.check_output(['ipconfig', '/all'], text=True)
            
            # Parse the output
            current_adapter = None
            for line in output.split('\n'):
                line = line.strip()
                
                if 'Ethernet adapter' in line or 'Wireless LAN adapter' in line:
                    current_adapter = line
                    
                if current_adapter and 'DHCP Enabled' in line and 'Yes' in line:
                    # This adapter uses DHCP
                    continue
                    
                if current_adapter:
                    if 'IPv4 Address' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            lease_info['current_ip'] = match.group(1)
                    elif 'DHCP Server' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            lease_info['dhcp_server'] = match.group(1)
                    elif 'Lease Obtained' in line:
                        # Parse date/time
                        date_match = re.search(r':\s*(.+)$', line)
                        if date_match:
                            lease_info['lease_obtained'] = date_match.group(1).strip()
                    elif 'Lease Expires' in line:
                        date_match = re.search(r':\s*(.+)$', line)
                        if date_match:
                            lease_info['lease_expires'] = date_match.group(1).strip()
                    elif 'Default Gateway' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            lease_info['gateway'] = match.group(1)
                    elif 'DNS Servers' in line:
                        matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if matches:
                            lease_info['dns_servers'] = matches
                            
        except Exception as e:
            lease_info['error'] = str(e)
            
        return lease_info
    
    def _parse_unix_lease(self) -> Dict[str, Any]:
        """Parse Unix/Linux/macOS DHCP lease information"""
        lease_info = {}
        
        try:
            system = platform.system().lower()
            
            if system == 'darwin':  # macOS
                # Try to get info from system configuration
                try:
                    output = subprocess.check_output(
                        ['ipconfig', 'getpacket', 'en0'], 
                        text=True, stderr=subprocess.DEVNULL
                    )
                    
                    for line in output.split('\n'):
                        if 'yiaddr' in line:
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                lease_info['current_ip'] = match.group(1)
                        elif 'siaddr' in line:
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                lease_info['dhcp_server'] = match.group(1)
                        elif 'router' in line:
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                lease_info['gateway'] = match.group(1)
                        elif 'domain_name_server' in line:
                            matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if matches:
                                lease_info['dns_servers'] = matches
                except:
                    pass
                    
            else:  # Linux
                # Try common lease file locations
                lease_files = [
                    '/var/lib/dhcp/dhclient.leases',
                    '/var/lib/dhclient/dhclient.leases',
                    '/var/db/dhclient.leases'
                ]
                
                for lease_file in lease_files:
                    try:
                        with open(lease_file, 'r') as f:
                            content = f.read()
                            
                        # Parse last lease
                        leases = content.split('lease {')
                        if len(leases) > 1:
                            last_lease = leases[-1]
                            
                            # Extract information
                            ip_match = re.search(r'fixed-address\s+(\d+\.\d+\.\d+\.\d+)', last_lease)
                            if ip_match:
                                lease_info['current_ip'] = ip_match.group(1)
                                
                            server_match = re.search(r'option dhcp-server-identifier\s+(\d+\.\d+\.\d+\.\d+)', last_lease)
                            if server_match:
                                lease_info['dhcp_server'] = server_match.group(1)
                                
                            router_match = re.search(r'option routers\s+(\d+\.\d+\.\d+\.\d+)', last_lease)
                            if router_match:
                                lease_info['gateway'] = router_match.group(1)
                                
                            dns_match = re.search(r'option domain-name-servers\s+([^;]+)', last_lease)
                            if dns_match:
                                dns_servers = re.findall(r'(\d+\.\d+\.\d+\.\d+)', dns_match.group(1))
                                lease_info['dns_servers'] = dns_servers
                                
                        break
                    except:
                        continue
                        
        except Exception as e:
            lease_info['error'] = str(e)
            
        return lease_info
    
    def _renew_windows_lease(self) -> bool:
        """Renew DHCP lease on Windows"""
        try:
            # Release current lease
            subprocess.run(['ipconfig', '/release'], capture_output=True, check=True)
            time.sleep(1)
            
            # Renew lease
            result = subprocess.run(['ipconfig', '/renew'], capture_output=True, check=True)
            return result.returncode == 0
        except:
            return False
    
    def _renew_macos_lease(self) -> bool:
        """Renew DHCP lease on macOS"""
        try:
            # Try to renew on common interfaces
            interfaces = ['en0', 'en1']
            success = False
            
            for interface in interfaces:
                try:
                    subprocess.run(['sudo', 'ipconfig', 'set', interface, 'DHCP'], 
                                 capture_output=True, check=True)
                    success = True
                except:
                    continue
                    
            return success
        except:
            return False
    
    def _renew_linux_lease(self) -> bool:
        """Renew DHCP lease on Linux"""
        try:
            # Try different DHCP clients
            dhcp_clients = ['dhclient', 'dhcpcd', 'systemd-networkd']
            
            for client in dhcp_clients:
                try:
                    if client == 'dhclient':
                        # Release and renew
                        subprocess.run(['sudo', 'dhclient', '-r'], capture_output=True)
                        time.sleep(1)
                        result = subprocess.run(['sudo', 'dhclient'], capture_output=True)
                        return result.returncode == 0
                    elif client == 'dhcpcd':
                        result = subprocess.run(['sudo', 'dhcpcd', '-n'], capture_output=True)
                        return result.returncode == 0
                    elif client == 'systemd-networkd':
                        result = subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-networkd'], 
                                              capture_output=True)
                        return result.returncode == 0
                except:
                    continue
                    
            return False
        except:
            return False


# Convenience functions for Claude Code

def discover_dhcp_servers(interface: Optional[str] = None, timeout: int = 5) -> List[Dict[str, Any]]:
    """Discover DHCP servers on the network"""
    diag = DHCPDiagnostics()
    return diag.discover_dhcp_servers(interface, timeout)


def check_ip_conflicts(ip_address: Optional[str] = None) -> List[Dict[str, Any]]:
    """Check for IP address conflicts"""
    diag = DHCPDiagnostics()
    return diag.detect_ip_conflicts(ip_address)


def get_lease_info() -> Dict[str, Any]:
    """Get current DHCP lease information"""
    diag = DHCPDiagnostics()
    return diag.analyze_dhcp_lease()


def find_rogue_dhcp_servers(authorized_servers: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Detect potential rogue DHCP servers"""
    diag = DHCPDiagnostics()
    return diag.detect_rogue_dhcp_servers(authorized_servers)


def test_dhcp_renewal() -> Dict[str, Any]:
    """Test DHCP lease renewal"""
    diag = DHCPDiagnostics()
    return diag.test_lease_renewal()


def diagnose_dhcp_issue(issue_type: str) -> Dict[str, Any]:
    """
    Comprehensive DHCP diagnosis based on issue type
    
    Args:
        issue_type: One of 'no_ip', 'conflict', 'renewal', 'rogue', 'general'
        
    Returns:
        Comprehensive diagnosis with recommendations
    """
    diagnosis = {
        'issue_type': issue_type,
        'timestamp': datetime.now().isoformat(),
        'findings': {},
        'recommendations': []
    }
    
    diag = DHCPDiagnostics()
    
    if issue_type == 'no_ip':
        # Can't get IP address
        diagnosis['findings']['dhcp_servers'] = diag.discover_dhcp_servers()
        diagnosis['findings']['current_lease'] = diag.analyze_dhcp_lease()
        
        if not diagnosis['findings']['dhcp_servers']:
            diagnosis['recommendations'].append('No DHCP servers found. Check network cable/WiFi connection.')
            diagnosis['recommendations'].append('Verify DHCP service is running on the network.')
        elif diagnosis['findings']['current_lease'].get('status') == 'expired':
            diagnosis['recommendations'].append('DHCP lease has expired. Try renewing the lease.')
            
    elif issue_type == 'conflict':
        # IP conflict detected
        diagnosis['findings']['conflicts'] = diag.detect_ip_conflicts()
        diagnosis['findings']['current_lease'] = diag.analyze_dhcp_lease()
        
        if diagnosis['findings']['conflicts']:
            diagnosis['recommendations'].append('IP conflict detected. Release and renew DHCP lease.')
            diagnosis['recommendations'].append('Contact network administrator if problem persists.')
            
    elif issue_type == 'renewal':
        # Lease renewal issues
        diagnosis['findings']['renewal_test'] = diag.test_lease_renewal()
        diagnosis['findings']['dhcp_servers'] = diag.discover_dhcp_servers()
        
        if not diagnosis['findings']['renewal_test']['renewal_successful']:
            diagnosis['recommendations'].append('Lease renewal failed. Check DHCP server availability.')
            diagnosis['recommendations'].append('Try manual IP configuration as temporary workaround.')
            
    elif issue_type == 'rogue':
        # Suspected rogue DHCP server
        diagnosis['findings']['rogue_servers'] = diag.detect_rogue_dhcp_servers()
        diagnosis['findings']['all_servers'] = diag.discover_dhcp_servers(timeout=10)
        
        if diagnosis['findings']['rogue_servers']:
            diagnosis['recommendations'].append('CRITICAL: Potential rogue DHCP server detected!')
            diagnosis['recommendations'].append('Immediately notify network security team.')
            diagnosis['recommendations'].append('Document all server IPs and configurations found.')
            
    else:  # general
        # General DHCP health check
        diagnosis['findings']['lease_info'] = diag.analyze_dhcp_lease()
        diagnosis['findings']['dhcp_servers'] = diag.discover_dhcp_servers()
        diagnosis['findings']['conflicts'] = diag.detect_ip_conflicts()
        
        # Provide general health assessment
        if diagnosis['findings']['lease_info'].get('status') == 'active':
            diagnosis['recommendations'].append('DHCP configuration appears healthy.')
        else:
            diagnosis['recommendations'].append('DHCP configuration may need attention.')
            
    return diagnosis