#!/usr/bin/env python3
"""
Routing Diagnostics Module
Advanced routing analysis and troubleshooting tools for SuperSleuth Network

This module provides comprehensive routing diagnostic capabilities that Claude Code
can use to diagnose routing-related network issues including path analysis,
MTU discovery, gateway health checks, and route stability monitoring.
"""

import socket
import struct
import time
import subprocess
import platform
import re
import ipaddress
import os
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
from collections import defaultdict

try:
    import netifaces
except ImportError:
    netifaces = None

try:
    import psutil
except ImportError:
    psutil = None

from ..utils.logger import get_logger
from ..core.diagnostic import BaseDiagnostic, DiagnosticResult


logger = get_logger("RoutingDiagnostics")


class RoutingDiagnostics(BaseDiagnostic):
    """
    Advanced routing diagnostic tools for troubleshooting network path issues
    
    Common use cases:
    - Can't reach remote networks
    - Intermittent connection drops
    - Slow network performance
    - Routing loops
    - Gateway not responding
    """
    
    def __init__(self, config: Dict = None):
        if config is None:
            config = {'client_name': 'Routing Test'}
        super().__init__(config)
        self.name = "Routing Diagnostics"
        self.description = "Advanced routing analysis and path diagnostics"
        
        # Platform-specific commands
        self.is_windows = platform.system() == 'Windows'
        self.is_macos = platform.system() == 'Darwin'
        self.is_linux = platform.system() == 'Linux'
        
        # ICMP packet constants
        self.ICMP_ECHO_REQUEST = 8
        self.ICMP_ECHO_REPLY = 0
        self.ICMP_TTL_EXCEEDED = 11
        self.ICMP_DEST_UNREACHABLE = 3
        
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met for routing diagnostics"""
        try:
            # Check if we can run basic routing commands
            if self.is_windows:
                result = subprocess.run(['route', 'print'], capture_output=True, timeout=2)
            elif self.is_macos:
                result = subprocess.run(['netstat', '-nr'], capture_output=True, timeout=2)
            else:
                result = subprocess.run(['ip', 'route'], capture_output=True, timeout=2)
                
            return result.returncode == 0
        except Exception:
            return False
        
    def _run_diagnostic(self, result: DiagnosticResult):
        """Execute comprehensive routing diagnostics"""
        try:
            # Get default gateway first
            gateway_info = self.get_default_gateway()
            if gateway_info:
                result.results['default_gateway'] = gateway_info
            else:
                result.add_warning("Could not determine default gateway")
                
            # Analyze route table
            routes = self.analyze_route_table()
            result.results['route_table'] = routes
            
            # Check gateway health
            if gateway_info:
                gateway_health = self.check_gateway_health(gateway_info['gateway'])
                result.results['gateway_health'] = gateway_health
                
                if not gateway_health['reachable']:
                    result.add_warning("Default gateway is not responding")
                    result.add_recommendation("Check gateway device status and local network connection")
                    
            result.complete(result.results)
            
        except Exception as e:
            logger.error(f"Routing diagnostic failed: {e}")
            result.fail(str(e))
            
    def analyze_route_table(self) -> Dict[str, Any]:
        """
        Analyze system routing table
        
        Returns:
            Dict containing route analysis including:
            - routes: List of route entries
            - route_count: Total number of routes
            - interface_routes: Routes grouped by interface
            - potential_issues: List of identified issues
        """
        try:
            routes = []
            interface_routes = defaultdict(list)
            potential_issues = []
            
            if self.is_windows:
                cmd = ['route', 'print']
            elif self.is_macos:
                cmd = ['netstat', '-nr']
            else:  # Linux
                cmd = ['ip', 'route', 'show']
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                routes_parsed = self._parse_route_output(result.stdout)
                routes = routes_parsed
                
                # Group by interface
                for route in routes:
                    if 'interface' in route:
                        interface_routes[route['interface']].append(route)
                        
                # Check for potential issues
                if self._has_multiple_default_routes(routes):
                    potential_issues.append("Multiple default routes detected - may cause routing conflicts")
                    
                if self._has_overlapping_subnets(routes):
                    potential_issues.append("Overlapping subnet routes detected")
                    
                if len(routes) > 100:
                    potential_issues.append("Large number of routes - may impact performance")
                    
            return {
                'routes': routes,
                'route_count': len(routes),
                'interface_routes': dict(interface_routes),
                'potential_issues': potential_issues,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze route table: {e}")
            return {
                'error': str(e),
                'routes': [],
                'route_count': 0
            }
            
    def _parse_route_output(self, output: str) -> List[Dict[str, str]]:
        """Parse route command output based on OS"""
        routes = []
        
        try:
            if self.is_windows:
                # Parse Windows route print output
                in_ipv4_section = False
                for line in output.splitlines():
                    if "IPv4 Route Table" in line:
                        in_ipv4_section = True
                        continue
                    if "IPv6 Route Table" in line:
                        break
                    if in_ipv4_section and line.strip():
                        parts = line.split()
                        if len(parts) >= 5 and parts[0][0].isdigit():
                            routes.append({
                                'destination': parts[0],
                                'netmask': parts[1],
                                'gateway': parts[2],
                                'interface': parts[3],
                                'metric': parts[4] if len(parts) > 4 else 'N/A'
                            })
                            
            elif self.is_macos:
                # Parse macOS netstat output
                for line in output.splitlines():
                    if line.startswith('Internet:') or not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 6 and not line.startswith('Destination'):
                        routes.append({
                            'destination': parts[0],
                            'gateway': parts[1],
                            'flags': parts[2],
                            'interface': parts[5] if len(parts) > 5 else 'N/A'
                        })
                        
            else:  # Linux
                # Parse Linux ip route output
                for line in output.splitlines():
                    if line.strip():
                        match = re.match(r'(\S+)\s+via\s+(\S+)\s+dev\s+(\S+)', line)
                        if match:
                            routes.append({
                                'destination': match.group(1),
                                'gateway': match.group(2),
                                'interface': match.group(3),
                                'raw': line
                            })
                        else:
                            # Direct route without gateway
                            match = re.match(r'(\S+)\s+dev\s+(\S+)', line)
                            if match:
                                routes.append({
                                    'destination': match.group(1),
                                    'gateway': 'Direct',
                                    'interface': match.group(2),
                                    'raw': line
                                })
                                
        except Exception as e:
            logger.error(f"Error parsing route output: {e}")
            
        return routes
        
    def get_default_gateway(self) -> Optional[Dict[str, str]]:
        """
        Get default gateway information
        
        Returns:
            Dict with gateway IP and interface, or None if not found
        """
        try:
            # Try netifaces first if available
            if netifaces:
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    gateway, interface = gateways['default'][netifaces.AF_INET]
                    return {
                        'gateway': gateway,
                        'interface': interface,
                        'method': 'netifaces'
                    }
                    
            # Fallback to system commands
            if self.is_windows:
                cmd = ['route', 'print', '0.0.0.0']
            elif self.is_macos:
                cmd = ['route', '-n', 'get', 'default']
            else:  # Linux
                cmd = ['ip', 'route', 'show', 'default']
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return self._parse_gateway_output(result.stdout)
                
        except Exception as e:
            logger.error(f"Failed to get default gateway: {e}")
            
        return None
        
    def _parse_gateway_output(self, output: str) -> Optional[Dict[str, str]]:
        """Parse gateway command output"""
        try:
            if self.is_windows:
                for line in output.splitlines():
                    if '0.0.0.0' in line and 'Active Routes' not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return {
                                'gateway': parts[2],
                                'interface': parts[3] if len(parts) > 3 else 'Unknown',
                                'method': 'route_command'
                            }
                            
            elif self.is_macos:
                gateway = None
                interface = None
                for line in output.splitlines():
                    if 'gateway:' in line:
                        gateway = line.split(':', 1)[1].strip()
                    elif 'interface:' in line:
                        interface = line.split(':', 1)[1].strip()
                if gateway:
                    return {
                        'gateway': gateway,
                        'interface': interface or 'Unknown',
                        'method': 'route_command'
                    }
                    
            else:  # Linux
                match = re.search(r'default via (\S+) dev (\S+)', output)
                if match:
                    return {
                        'gateway': match.group(1),
                        'interface': match.group(2),
                        'method': 'route_command'
                    }
                    
        except Exception as e:
            logger.error(f"Error parsing gateway output: {e}")
            
        return None
        
    def check_gateway_health(self, gateway_ip: str, count: int = 4) -> Dict[str, Any]:
        """
        Check default gateway health and responsiveness
        
        Args:
            gateway_ip: Gateway IP address
            count: Number of ping attempts
            
        Returns:
            Dict with gateway health metrics
        """
        try:
            ping_result = self.ping_host(gateway_ip, count=count)
            
            health_status = {
                'gateway_ip': gateway_ip,
                'reachable': ping_result['success'],
                'packet_loss': ping_result['packet_loss'],
                'avg_rtt': ping_result['avg_rtt'],
                'timestamp': datetime.now().isoformat()
            }
            
            # Add health assessment
            if ping_result['success']:
                if ping_result['packet_loss'] == 0:
                    health_status['status'] = 'healthy'
                elif ping_result['packet_loss'] < 25:
                    health_status['status'] = 'degraded'
                else:
                    health_status['status'] = 'poor'
            else:
                health_status['status'] = 'unreachable'
                
            return health_status
            
        except Exception as e:
            logger.error(f"Failed to check gateway health: {e}")
            return {
                'gateway_ip': gateway_ip,
                'reachable': False,
                'error': str(e),
                'status': 'error'
            }
            
    def ping_host(self, host: str, count: int = 4, timeout: int = 2) -> Dict[str, Any]:
        """
        Ping a host and return statistics
        
        Args:
            host: Target host IP or hostname
            count: Number of pings
            timeout: Timeout per ping in seconds
            
        Returns:
            Dict with ping results
        """
        try:
            if self.is_windows:
                cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 2)
            
            return self._parse_ping_output(result.stdout, result.returncode)
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'packet_loss': 100,
                'error': 'Timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'packet_loss': 100,
                'error': str(e)
            }
            
    def _parse_ping_output(self, output: str, return_code: int) -> Dict[str, Any]:
        """Parse ping command output"""
        results = {
            'success': return_code == 0,
            'packet_loss': 100,
            'min_rtt': None,
            'avg_rtt': None,
            'max_rtt': None,
            'raw_output': output
        }
        
        try:
            # Extract packet loss
            if self.is_windows:
                loss_match = re.search(r'\((\d+)% loss\)', output)
            else:
                loss_match = re.search(r'(\d+)% packet loss', output)
                
            if loss_match:
                results['packet_loss'] = int(loss_match.group(1))
                
            # Extract RTT statistics
            if self.is_windows:
                rtt_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
                if rtt_match:
                    results['min_rtt'] = int(rtt_match.group(1))
                    results['max_rtt'] = int(rtt_match.group(2))
                    results['avg_rtt'] = int(rtt_match.group(3))
            else:
                rtt_match = re.search(r'min/avg/max/[^=]+ = ([\d.]+)/([\d.]+)/([\d.]+)', output)
                if rtt_match:
                    results['min_rtt'] = float(rtt_match.group(1))
                    results['avg_rtt'] = float(rtt_match.group(2))
                    results['max_rtt'] = float(rtt_match.group(3))
                    
        except Exception as e:
            logger.error(f"Error parsing ping output: {e}")
            
        return results
        
    def enhanced_traceroute(self, target: str, max_hops: int = 30, 
                          timeout: int = 2, packets_per_hop: int = 3) -> Dict[str, Any]:
        """
        Perform enhanced traceroute with timing and packet loss metrics
        
        Args:
            target: Target host IP or hostname
            max_hops: Maximum number of hops
            timeout: Timeout per probe in seconds
            packets_per_hop: Number of packets per hop
            
        Returns:
            Dict with traceroute results and analysis
        """
        try:
            # Resolve hostname if needed
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {
                    'error': f'Cannot resolve hostname: {target}',
                    'target': target
                }
                
            if self.is_windows:
                cmd = ['tracert', '-h', str(max_hops), '-w', str(timeout * 1000), target]
            else:
                cmd = ['traceroute', '-m', str(max_hops), '-w', str(timeout), target]
                
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=max_hops * timeout * 2)
            
            hops = self._parse_traceroute_output(result.stdout)
            
            # Analyze the path
            analysis = self._analyze_traceroute_path(hops)
            
            return {
                'target': target,
                'target_ip': target_ip,
                'hops': hops,
                'hop_count': len(hops),
                'analysis': analysis,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'error': 'Traceroute timeout',
                'target': target
            }
        except Exception as e:
            logger.error(f"Enhanced traceroute failed: {e}")
            return {
                'error': str(e),
                'target': target
            }
            
    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute output"""
        hops = []
        
        try:
            for line in output.splitlines():
                if self.is_windows:
                    # Windows tracert format
                    match = re.match(r'\s*(\d+)\s+(.+)', line)
                    if match:
                        hop_num = int(match.group(1))
                        hop_data = match.group(2)
                        
                        # Extract RTT values and IP
                        rtt_values = []
                        ip_match = re.search(r'\[([\d.]+)\]', hop_data)
                        ip = ip_match.group(1) if ip_match else None
                        
                        for rtt_match in re.finditer(r'(\d+)\s*ms', hop_data):
                            rtt_values.append(int(rtt_match.group(1)))
                            
                        if '*' in hop_data and not rtt_values:
                            hops.append({
                                'hop': hop_num,
                                'ip': None,
                                'hostname': None,
                                'rtt_values': [],
                                'avg_rtt': None,
                                'packet_loss': 100
                            })
                        elif ip or rtt_values:
                            hops.append({
                                'hop': hop_num,
                                'ip': ip,
                                'hostname': self._extract_hostname(hop_data),
                                'rtt_values': rtt_values,
                                'avg_rtt': sum(rtt_values) / len(rtt_values) if rtt_values else None,
                                'packet_loss': (3 - len(rtt_values)) * 33.33
                            })
                else:
                    # Unix traceroute format
                    match = re.match(r'\s*(\d+)\s+(.+)', line)
                    if match:
                        hop_num = int(match.group(1))
                        hop_data = match.group(2)
                        
                        # Extract IP and RTT values
                        ip_match = re.search(r'\(([\d.]+)\)', hop_data)
                        ip = ip_match.group(1) if ip_match else None
                        
                        rtt_values = []
                        for rtt_match in re.finditer(r'([\d.]+)\s*ms', hop_data):
                            rtt_values.append(float(rtt_match.group(1)))
                            
                        if '*' in hop_data and not rtt_values:
                            hops.append({
                                'hop': hop_num,
                                'ip': None,
                                'hostname': None,
                                'rtt_values': [],
                                'avg_rtt': None,
                                'packet_loss': 100
                            })
                        elif ip or rtt_values:
                            hops.append({
                                'hop': hop_num,
                                'ip': ip,
                                'hostname': self._extract_hostname(hop_data),
                                'rtt_values': rtt_values,
                                'avg_rtt': sum(rtt_values) / len(rtt_values) if rtt_values else None,
                                'packet_loss': (3 - len(rtt_values)) * 33.33
                            })
                            
        except Exception as e:
            logger.error(f"Error parsing traceroute output: {e}")
            
        return hops
        
    def _extract_hostname(self, hop_data: str) -> Optional[str]:
        """Extract hostname from hop data"""
        # Remove IP addresses and RTT values
        cleaned = re.sub(r'\[([\d.]+)\]|\(([\d.]+)\)|[\d.]+\s*ms|\*', '', hop_data)
        cleaned = cleaned.strip()
        
        # Return cleaned hostname if it's not empty and not just numbers
        if cleaned and not cleaned.replace('.', '').isdigit():
            return cleaned
        return None
        
    def _analyze_traceroute_path(self, hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze traceroute path for issues"""
        analysis = {
            'total_hops': len(hops),
            'unreachable_hops': 0,
            'high_latency_hops': [],
            'packet_loss_hops': [],
            'potential_issues': []
        }
        
        prev_rtt = None
        
        for i, hop in enumerate(hops):
            # Count unreachable hops
            if hop['packet_loss'] == 100:
                analysis['unreachable_hops'] += 1
                
            # Identify high latency (> 100ms)
            if hop['avg_rtt'] and hop['avg_rtt'] > 100:
                analysis['high_latency_hops'].append({
                    'hop': hop['hop'],
                    'avg_rtt': hop['avg_rtt'],
                    'ip': hop['ip']
                })
                
            # Identify packet loss
            if 0 < hop['packet_loss'] < 100:
                analysis['packet_loss_hops'].append({
                    'hop': hop['hop'],
                    'packet_loss': hop['packet_loss'],
                    'ip': hop['ip']
                })
                
            # Check for sudden latency increases
            if prev_rtt and hop['avg_rtt'] and hop['avg_rtt'] > prev_rtt * 3:
                analysis['potential_issues'].append(
                    f"Large latency increase at hop {hop['hop']} ({prev_rtt}ms -> {hop['avg_rtt']}ms)"
                )
                
            if hop['avg_rtt']:
                prev_rtt = hop['avg_rtt']
                
        # Add general analysis
        if analysis['unreachable_hops'] > len(hops) * 0.3:
            analysis['potential_issues'].append("Many unreachable hops - possible firewall blocking ICMP")
            
        if len(analysis['high_latency_hops']) > 0:
            analysis['potential_issues'].append(f"{len(analysis['high_latency_hops'])} hops with high latency")
            
        if len(analysis['packet_loss_hops']) > 0:
            analysis['potential_issues'].append(f"{len(analysis['packet_loss_hops'])} hops with packet loss")
            
        return analysis
        
    def discover_path_mtu(self, target: str, start_mtu: int = 1500, 
                         min_mtu: int = 576) -> Dict[str, Any]:
        """
        Discover Path MTU to target using Don't Fragment bit
        
        Args:
            target: Target host IP or hostname
            start_mtu: Starting MTU size to test
            min_mtu: Minimum MTU to test
            
        Returns:
            Dict with MTU discovery results
        """
        try:
            # Resolve hostname
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {
                    'error': f'Cannot resolve hostname: {target}',
                    'target': target
                }
                
            discovered_mtu = self._binary_search_mtu(target_ip, min_mtu, start_mtu)
            
            # Get common MTU reference
            common_mtus = {
                1500: "Ethernet (standard)",
                1492: "PPPoE",
                1480: "IPv6 tunnels",
                1472: "VPN (common)",
                1460: "TCP MSS for 1500 MTU",
                1400: "VPN/Tunnel (conservative)",
                576: "Internet minimum"
            }
            
            mtu_type = common_mtus.get(discovered_mtu, "Non-standard")
            
            return {
                'target': target,
                'target_ip': target_ip,
                'discovered_mtu': discovered_mtu,
                'mtu_type': mtu_type,
                'standard_ethernet_mtu': 1500,
                'mtu_difference': 1500 - discovered_mtu,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"MTU discovery failed: {e}")
            return {
                'error': str(e),
                'target': target
            }
            
    def _binary_search_mtu(self, target_ip: str, min_mtu: int, max_mtu: int) -> int:
        """Binary search for maximum working MTU"""
        while min_mtu < max_mtu:
            test_mtu = (min_mtu + max_mtu + 1) // 2
            
            if self._test_mtu_size(target_ip, test_mtu):
                min_mtu = test_mtu
            else:
                max_mtu = test_mtu - 1
                
        return min_mtu
        
    def _test_mtu_size(self, target_ip: str, mtu_size: int) -> bool:
        """Test if specific MTU size works"""
        try:
            # Calculate payload size (MTU - IP header - ICMP header)
            payload_size = mtu_size - 28  # 20 bytes IP + 8 bytes ICMP
            
            if self.is_windows:
                cmd = ['ping', '-n', '1', '-l', str(payload_size), '-f', target_ip]
            elif self.is_macos:
                cmd = ['ping', '-c', '1', '-D', '-s', str(payload_size), target_ip]
            else:  # Linux
                cmd = ['ping', '-c', '1', '-M', 'do', '-s', str(payload_size), target_ip]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            
            # Check if packet was sent successfully
            if self.is_windows:
                return "Reply from" in result.stdout
            else:
                return result.returncode == 0
                
        except Exception:
            return False
            
    def monitor_route_stability(self, target: str, duration: int = 30, 
                              interval: int = 5) -> Dict[str, Any]:
        """
        Monitor route stability over time
        
        Args:
            target: Target host to monitor route to
            duration: Monitoring duration in seconds
            interval: Check interval in seconds
            
        Returns:
            Dict with route stability analysis
        """
        try:
            # Resolve hostname
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {
                    'error': f'Cannot resolve hostname: {target}',
                    'target': target
                }
                
            route_changes = []
            route_history = []
            start_time = time.time()
            last_route = None
            
            while time.time() - start_time < duration:
                # Get current route
                current_route = self._get_route_to_target(target_ip)
                route_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'route': current_route
                })
                
                # Check for changes
                if last_route and current_route != last_route:
                    route_changes.append({
                        'timestamp': datetime.now().isoformat(),
                        'old_route': last_route,
                        'new_route': current_route
                    })
                    
                last_route = current_route
                time.sleep(interval)
                
            # Analyze results
            analysis = {
                'target': target,
                'target_ip': target_ip,
                'duration': duration,
                'checks_performed': len(route_history),
                'route_changes': len(route_changes),
                'stability_percentage': ((len(route_history) - len(route_changes)) / len(route_history)) * 100,
                'changes': route_changes,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add assessment
            if len(route_changes) == 0:
                analysis['assessment'] = 'Stable - No route changes detected'
            elif len(route_changes) < 3:
                analysis['assessment'] = 'Mostly stable - Minor route changes'
            else:
                analysis['assessment'] = 'Unstable - Frequent route changes detected'
                
            return analysis
            
        except Exception as e:
            logger.error(f"Route stability monitoring failed: {e}")
            return {
                'error': str(e),
                'target': target
            }
            
    def _get_route_to_target(self, target_ip: str) -> Optional[str]:
        """Get the current route to target IP"""
        try:
            if self.is_windows:
                cmd = ['route', 'print', target_ip]
            elif self.is_macos:
                cmd = ['route', 'get', target_ip]
            else:  # Linux
                cmd = ['ip', 'route', 'get', target_ip]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                # Extract key route info
                if self.is_linux:
                    match = re.search(r'via (\S+) dev (\S+)', result.stdout)
                    if match:
                        return f"via {match.group(1)} dev {match.group(2)}"
                elif self.is_macos:
                    gateway_match = re.search(r'gateway: (\S+)', result.stdout)
                    if gateway_match:
                        return f"via {gateway_match.group(1)}"
                        
                return result.stdout.strip()[:100]  # Return first 100 chars
                
        except Exception:
            pass
            
        return None
        
    def _has_multiple_default_routes(self, routes: List[Dict[str, str]]) -> bool:
        """Check if there are multiple default routes"""
        default_count = 0
        
        for route in routes:
            dest = route.get('destination', '')
            if dest in ['0.0.0.0', 'default', '0.0.0.0/0']:
                default_count += 1
                
        return default_count > 1
        
    def _has_overlapping_subnets(self, routes: List[Dict[str, str]]) -> bool:
        """Check for overlapping subnet routes"""
        networks = []
        
        for route in routes:
            dest = route.get('destination', '')
            if '/' in dest:  # CIDR notation
                try:
                    net = ipaddress.ip_network(dest, strict=False)
                    for existing_net in networks:
                        if net.overlaps(existing_net):
                            return True
                    networks.append(net)
                except Exception:
                    pass
                    
        return False
        
    def analyze_asymmetric_routing(self, target: str) -> Dict[str, Any]:
        """
        Check for asymmetric routing by analyzing forward and reverse paths
        
        Args:
            target: Target host to analyze
            
        Returns:
            Dict with asymmetric routing analysis
        """
        try:
            # Get forward path
            forward_trace = self.enhanced_traceroute(target, max_hops=15)
            
            # Try to determine our external IP
            external_ip = self._get_external_ip()
            
            analysis = {
                'target': target,
                'forward_path': forward_trace,
                'external_ip': external_ip,
                'analysis': {
                    'forward_hop_count': len(forward_trace.get('hops', [])),
                    'notes': []
                },
                'timestamp': datetime.now().isoformat()
            }
            
            # Analyze for common asymmetric patterns
            if forward_trace.get('hops'):
                # Check for private IP addresses in path
                private_ips_in_path = 0
                for hop in forward_trace['hops']:
                    if hop.get('ip'):
                        try:
                            ip = ipaddress.ip_address(hop['ip'])
                            if ip.is_private:
                                private_ips_in_path += 1
                        except Exception:
                            pass
                            
                if private_ips_in_path > 1:
                    analysis['analysis']['notes'].append(
                        f"Multiple private IPs in path ({private_ips_in_path}) - possible complex routing"
                    )
                    
            return analysis
            
        except Exception as e:
            logger.error(f"Asymmetric routing analysis failed: {e}")
            return {
                'error': str(e),
                'target': target
            }
            
    def _get_external_ip(self) -> Optional[str]:
        """Try to determine external IP address"""
        try:
            # Use a simple socket connection to determine external IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            external_ip = s.getsockname()[0]
            s.close()
            return external_ip
        except Exception:
            return None


# Standalone diagnostic functions for direct use

def analyze_routes() -> Dict[str, Any]:
    """Analyze system routing table"""
    diag = RoutingDiagnostics()
    return diag.analyze_route_table()


def check_gateway() -> Dict[str, Any]:
    """Check default gateway health"""
    diag = RoutingDiagnostics()
    gateway_info = diag.get_default_gateway()
    
    if not gateway_info:
        return {
            'error': 'Could not determine default gateway',
            'status': 'unknown'
        }
        
    return diag.check_gateway_health(gateway_info['gateway'])


def trace_route(target: str, max_hops: int = 30) -> Dict[str, Any]:
    """Perform enhanced traceroute to target"""
    diag = RoutingDiagnostics()
    return diag.enhanced_traceroute(target, max_hops=max_hops)


def discover_mtu(target: str) -> Dict[str, Any]:
    """Discover Path MTU to target"""
    diag = RoutingDiagnostics()
    return diag.discover_path_mtu(target)


def monitor_route(target: str, duration: int = 30) -> Dict[str, Any]:
    """Monitor route stability to target"""
    diag = RoutingDiagnostics()
    return diag.monitor_route_stability(target, duration=duration)


def check_asymmetric_routing(target: str) -> Dict[str, Any]:
    """Check for asymmetric routing to target"""
    diag = RoutingDiagnostics()
    return diag.analyze_asymmetric_routing(target)


if __name__ == "__main__":
    # Quick test
    print("Testing Routing Diagnostics...")
    
    # Test route analysis
    routes = analyze_routes()
    print(f"\nFound {routes.get('route_count', 0)} routes")
    
    # Test gateway
    gateway = check_gateway()
    print(f"\nGateway status: {gateway.get('status', 'unknown')}")
    
    # Test traceroute to Google DNS
    trace = trace_route("8.8.8.8", max_hops=10)
    print(f"\nTraceroute completed with {len(trace.get('hops', []))} hops")