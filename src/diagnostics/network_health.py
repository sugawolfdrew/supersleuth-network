#!/usr/bin/env python3
"""
Network Interface Health Check Module
Core diagnostic tool for SuperSleuth Network toolkit

This module provides the baseline diagnostics that Claude Code uses
when approaching any network issue. It's the "check vital signs" tool.
"""

import psutil
import subprocess
import platform
import socket
from typing import Dict, List, Any, Optional
from datetime import datetime
import netifaces

from ..utils.logger import get_logger
from ..core.diagnostic import BaseDiagnostic, DiagnosticResult
from ..core.authorization import AuthorizationRequest, RiskLevel


class NetworkHealthCheck(BaseDiagnostic):
    """
    Network interface health diagnostics
    
    This is the go-to first diagnostic for any network issue.
    Provides comprehensive health check of all network interfaces.
    """
    
    def __init__(self, config: Dict = None):
        if config is None:
            config = {'client_name': 'Local Test'}
        super().__init__(config)
        self.name = "Network Health Check"
        self.description = "Comprehensive network interface diagnostics"
    
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        # This diagnostic only requires psutil and netifaces which we already import
        return True
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'network_metadata_only',
            'risk_level': 'low',
            'description': 'Read-only network interface health check'
        }
    
    def get_interface_stats(self, interface: str) -> Dict[str, Any]:
        """Get detailed statistics for a specific network interface"""
        
        stats = psutil.net_if_stats()[interface]
        addrs = psutil.net_if_addrs().get(interface, [])
        io_counters = psutil.net_io_counters(pernic=True).get(interface)
        
        # Get IPv4 and IPv6 addresses
        ipv4_addrs = [addr.address for addr in addrs if addr.family == socket.AF_INET]
        ipv6_addrs = [addr.address for addr in addrs if addr.family == socket.AF_INET6]
        mac_addr = next((addr.address for addr in addrs if addr.family == psutil.AF_LINK), None)
        
        interface_info = {
            'name': interface,
            'is_up': stats.isup,
            'speed_mbps': stats.speed,
            'mtu': stats.mtu,
            'mac_address': mac_addr,
            'ipv4_addresses': ipv4_addrs,
            'ipv6_addresses': ipv6_addrs,
            'statistics': {}
        }
        
        if io_counters:
            # Calculate error rates
            total_packets = io_counters.packets_sent + io_counters.packets_recv
            error_rate = 0
            if total_packets > 0:
                total_errors = io_counters.errin + io_counters.errout
                error_rate = (total_errors / total_packets) * 100
            
            interface_info['statistics'] = {
                'bytes_sent': io_counters.bytes_sent,
                'bytes_recv': io_counters.bytes_recv,
                'packets_sent': io_counters.packets_sent,
                'packets_recv': io_counters.packets_recv,
                'errors_in': io_counters.errin,
                'errors_out': io_counters.errout,
                'drops_in': io_counters.dropin,
                'drops_out': io_counters.dropout,
                'error_rate_percent': round(error_rate, 3)
            }
            
            # Health assessment based on error rates
            if error_rate > 5:
                interface_info['health_status'] = 'critical'
                interface_info['health_message'] = f'High error rate: {error_rate:.1f}%'
            elif error_rate > 1:
                interface_info['health_status'] = 'warning'
                interface_info['health_message'] = f'Elevated error rate: {error_rate:.1f}%'
            else:
                interface_info['health_status'] = 'healthy'
                interface_info['health_message'] = 'Interface operating normally'
        
        return interface_info
    
    def check_connectivity(self) -> Dict[str, Any]:
        """Check basic network connectivity"""
        
        connectivity = {
            'gateway_reachable': False,
            'dns_functional': False,
            'internet_reachable': False,
            'details': {}
        }
        
        # Get default gateway
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        
        if default_gateway:
            gateway_ip = default_gateway[0]
            
            # Test gateway connectivity
            if self._ping_host(gateway_ip):
                connectivity['gateway_reachable'] = True
                connectivity['details']['gateway'] = {
                    'ip': gateway_ip,
                    'interface': default_gateway[1],
                    'status': 'reachable'
                }
            else:
                connectivity['details']['gateway'] = {
                    'ip': gateway_ip,
                    'interface': default_gateway[1],
                    'status': 'unreachable',
                    'message': 'Cannot reach default gateway - check cable/WiFi connection'
                }
        
        # Test DNS resolution
        try:
            socket.gethostbyname('google.com')
            connectivity['dns_functional'] = True
            connectivity['details']['dns'] = {
                'status': 'working',
                'test_domain': 'google.com'
            }
        except socket.gaierror:
            connectivity['details']['dns'] = {
                'status': 'failed',
                'message': 'DNS resolution not working - check DNS settings'
            }
        
        # Test internet connectivity
        if connectivity['dns_functional']:
            if self._ping_host('8.8.8.8'):
                connectivity['internet_reachable'] = True
                connectivity['details']['internet'] = {
                    'status': 'connected',
                    'test_host': '8.8.8.8 (Google DNS)'
                }
            else:
                connectivity['details']['internet'] = {
                    'status': 'unreachable',
                    'message': 'Cannot reach internet - possible firewall or routing issue'
                }
        
        return connectivity
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get summary of active network connections"""
        
        connections = []
        conn_summary = {
            'total': 0,
            'by_state': {},
            'by_type': {'tcp': 0, 'udp': 0},
            'top_processes': {}
        }
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_summary['total'] += 1
                
                # Count by state
                if conn.status:
                    conn_summary['by_state'][conn.status] = \
                        conn_summary['by_state'].get(conn.status, 0) + 1
                
                # Count by type
                conn_type = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                conn_summary['by_type'][conn_type] += 1
                
                # Track top processes
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        conn_summary['top_processes'][proc_name] = \
                            conn_summary['top_processes'].get(proc_name, 0) + 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        
        except psutil.AccessDenied:
            conn_summary['error'] = 'Need elevated privileges for full connection details'
        
        # Sort top processes by connection count
        top_procs = sorted(conn_summary['top_processes'].items(), 
                          key=lambda x: x[1], reverse=True)[:5]
        conn_summary['top_processes'] = dict(top_procs)
        
        return conn_summary
    
    def _ping_host(self, host: str, count: int = 2) -> bool:
        """Simple ping test to check if host is reachable"""
        
        cmd = ['ping', '-c', str(count), host]
        if platform.system() == 'Windows':
            cmd = ['ping', '-n', str(count), host]
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _run_diagnostic(self, result: DiagnosticResult):
        """Execute the network health diagnostic"""
        
        findings = {
            'interfaces': {},
            'connectivity': {},
            'connections': {},
            'issues_found': [],
            'recommendations': []
        }
        
        # Check all network interfaces
        self.logger.info("Checking network interface health...")
        interfaces = psutil.net_if_stats()
        
        for iface_name in interfaces:
            # Skip loopback interfaces
            if 'lo' in iface_name.lower():
                continue
                
            try:
                iface_stats = self.get_interface_stats(iface_name)
                findings['interfaces'][iface_name] = iface_stats
                
                # Flag any issues
                if iface_stats.get('health_status') == 'critical':
                    findings['issues_found'].append({
                        'severity': 'high',
                        'interface': iface_name,
                        'issue': iface_stats['health_message']
                    })
                elif iface_stats.get('health_status') == 'warning':
                    findings['issues_found'].append({
                        'severity': 'medium',
                        'interface': iface_name,
                        'issue': iface_stats['health_message']
                    })
                    
            except Exception as e:
                self.logger.error(f"Error checking interface {iface_name}: {str(e)}")
        
        # Check connectivity
        self.logger.info("Testing network connectivity...")
        findings['connectivity'] = self.check_connectivity()
        
        # Add connectivity issues
        if not findings['connectivity']['gateway_reachable']:
            findings['issues_found'].append({
                'severity': 'critical',
                'category': 'connectivity',
                'issue': 'Cannot reach default gateway'
            })
            findings['recommendations'].append(
                "Check physical connection (cable/WiFi) and verify gateway IP"
            )
        
        if not findings['connectivity']['dns_functional']:
            findings['issues_found'].append({
                'severity': 'high',
                'category': 'connectivity',
                'issue': 'DNS resolution failing'
            })
            findings['recommendations'].append(
                "Check DNS server settings and verify DNS server is reachable"
            )
        
        # Get connection summary
        self.logger.info("Analyzing active connections...")
        findings['connections'] = self.get_active_connections()
        
        # Set overall result
        if any(issue['severity'] == 'critical' for issue in findings['issues_found']):
            result.complete({'status': 'critical', 'findings': findings})
            result.add_warning('Critical network issues detected')
        elif findings['issues_found']:
            result.complete({'status': 'warning', 'findings': findings})
            result.add_warning('Network issues detected that may impact performance')
        else:
            result.complete({'status': 'healthy', 'findings': findings})
        
        # Add recommendations
        for rec in findings['recommendations']:
            result.add_recommendation(rec)


def run_health_check():
    """Standalone function to run network health check"""
    
    print("\n🏥 NETWORK HEALTH CHECK")
    print("=" * 50)
    
    health_check = NetworkHealthCheck()
    result = health_check.run()
    
    # Display results
    print(f"\nStatus: {result.status.upper()}")
    
    if result.results and 'findings' in result.results:
        findings = result.results['findings']
        
        if findings.get('interfaces'):
            print("\n📊 INTERFACE HEALTH:")
            for iface, stats in findings['interfaces'].items():
                status_icon = "✅" if stats['health_status'] == 'healthy' else "⚠️"
                print(f"\n  {status_icon} {iface}:")
                print(f"     Status: {stats['health_message']}")
                if stats['is_up']:
                    print(f"     Speed: {stats['speed_mbps']} Mbps")
                    print(f"     MTU: {stats['mtu']}")
                    if 'statistics' in stats and stats['statistics']:
                        print(f"     Error Rate: {stats['statistics']['error_rate_percent']}%")
        
        if findings.get('connectivity'):
            print("\n🌐 CONNECTIVITY:")
            conn = findings['connectivity']
            print(f"   Gateway: {'✅' if conn['gateway_reachable'] else '❌'}")
            print(f"   DNS: {'✅' if conn['dns_functional'] else '❌'}")
            print(f"   Internet: {'✅' if conn['internet_reachable'] else '❌'}")
        
        if findings.get('connections'):
            print("\n📡 ACTIVE CONNECTIONS:")
            conn_summary = findings['connections']
            print(f"   Total: {conn_summary.get('total', 0)}")
            if 'by_state' in conn_summary:
                print("   By State:")
                for state, count in conn_summary['by_state'].items():
                    print(f"     - {state}: {count}")
    
    if result.warnings:
        print("\n⚠️  WARNINGS:")
        for warning in result.warnings:
            print(f"   • {warning}")
    
    if result.recommendations:
        print("\n💡 RECOMMENDATIONS:")
        for rec in result.recommendations:
            print(f"   • {rec}")
    
    return result


if __name__ == "__main__":
    run_health_check()