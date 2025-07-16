#!/usr/bin/env python3
"""
Network Interface Metrics Module
Provides detailed network interface statistics using psutil and netifaces

This module is designed to be used by Claude Code to gather network metrics
for diagnostic purposes. All functions are standalone and can be called
independently or combined as needed.
"""

import psutil
import netifaces
import socket
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from ..utils.logger import get_logger


logger = get_logger("NetworkMetrics")


def get_all_interfaces() -> List[str]:
    """Get list of all network interfaces on the system"""
    interfaces = []
    
    # Get interfaces from psutil
    for iface in psutil.net_if_stats():
        interfaces.append(iface)
    
    return sorted(list(set(interfaces)))


def get_interface_details(interface: str) -> Dict[str, Any]:
    """Get detailed information about a specific network interface
    
    Args:
        interface: Network interface name (e.g., 'eth0', 'en0', 'wlan0')
        
    Returns:
        Dict containing interface details including IP addresses, MAC, status
    """
    details = {
        'name': interface,
        'exists': False,
        'is_up': False,
        'addresses': {},
        'stats': {}
    }
    
    # Check if interface exists
    if interface not in psutil.net_if_stats():
        return details
    
    details['exists'] = True
    
    # Get interface status
    stats = psutil.net_if_stats()[interface]
    details['is_up'] = stats.isup
    details['speed_mbps'] = stats.speed
    details['mtu'] = stats.mtu
    details['duplex'] = stats.duplex.name if hasattr(stats.duplex, 'name') else 'unknown'
    
    # Get addresses using netifaces
    try:
        addrs = netifaces.ifaddresses(interface)
        
        # IPv4 addresses
        if netifaces.AF_INET in addrs:
            details['addresses']['ipv4'] = []
            for addr in addrs[netifaces.AF_INET]:
                details['addresses']['ipv4'].append({
                    'address': addr.get('addr'),
                    'netmask': addr.get('netmask'),
                    'broadcast': addr.get('broadcast')
                })
        
        # IPv6 addresses
        if netifaces.AF_INET6 in addrs:
            details['addresses']['ipv6'] = []
            for addr in addrs[netifaces.AF_INET6]:
                details['addresses']['ipv6'].append({
                    'address': addr.get('addr'),
                    'netmask': addr.get('netmask')
                })
        
        # MAC address
        if netifaces.AF_LINK in addrs:
            details['addresses']['mac'] = addrs[netifaces.AF_LINK][0].get('addr')
    
    except Exception as e:
        logger.warning(f"Could not get addresses for {interface}: {str(e)}")
    
    return details


def get_interface_io_stats(interface: str = None) -> Dict[str, Dict[str, int]]:
    """Get I/O statistics for network interfaces
    
    Args:
        interface: Specific interface name, or None for all interfaces
        
    Returns:
        Dict with interface names as keys and I/O stats as values
    """
    io_counters = psutil.net_io_counters(pernic=True)
    
    if interface:
        if interface in io_counters:
            stats = io_counters[interface]
            return {
                interface: {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errors_in': stats.errin,
                    'errors_out': stats.errout,
                    'drops_in': stats.dropin,
                    'drops_out': stats.dropout
                }
            }
        else:
            return {}
    
    # Return all interfaces
    result = {}
    for iface, stats in io_counters.items():
        result[iface] = {
            'bytes_sent': stats.bytes_sent,
            'bytes_recv': stats.bytes_recv,
            'packets_sent': stats.packets_sent,
            'packets_recv': stats.packets_recv,
            'errors_in': stats.errin,
            'errors_out': stats.errout,
            'drops_in': stats.dropin,
            'drops_out': stats.dropout
        }
    
    return result


def calculate_bandwidth_usage(interval: float = 1.0, interface: str = None) -> Dict[str, Dict[str, float]]:
    """Calculate real-time bandwidth usage for interfaces
    
    Args:
        interval: Time interval in seconds to measure bandwidth
        interface: Specific interface name, or None for all interfaces
        
    Returns:
        Dict with bandwidth usage in Mbps for each interface
    """
    # Get initial stats
    initial_stats = get_interface_io_stats(interface)
    
    # Wait for interval
    time.sleep(interval)
    
    # Get final stats
    final_stats = get_interface_io_stats(interface)
    
    # Calculate bandwidth
    bandwidth = {}
    
    for iface in final_stats:
        if iface in initial_stats:
            bytes_sent_delta = final_stats[iface]['bytes_sent'] - initial_stats[iface]['bytes_sent']
            bytes_recv_delta = final_stats[iface]['bytes_recv'] - initial_stats[iface]['bytes_recv']
            
            # Convert to Mbps
            upload_mbps = (bytes_sent_delta * 8) / (interval * 1_000_000)
            download_mbps = (bytes_recv_delta * 8) / (interval * 1_000_000)
            
            bandwidth[iface] = {
                'upload_mbps': round(upload_mbps, 2),
                'download_mbps': round(download_mbps, 2),
                'total_mbps': round(upload_mbps + download_mbps, 2)
            }
    
    return bandwidth


def get_interface_error_rates(interface: str = None) -> Dict[str, Dict[str, float]]:
    """Calculate error and drop rates for network interfaces
    
    Args:
        interface: Specific interface name, or None for all interfaces
        
    Returns:
        Dict with error and drop rates as percentages
    """
    io_stats = get_interface_io_stats(interface)
    
    error_rates = {}
    
    for iface, stats in io_stats.items():
        total_packets = stats['packets_sent'] + stats['packets_recv']
        total_errors = stats['errors_in'] + stats['errors_out']
        total_drops = stats['drops_in'] + stats['drops_out']
        
        if total_packets > 0:
            error_rate = (total_errors / total_packets) * 100
            drop_rate = (total_drops / total_packets) * 100
        else:
            error_rate = 0.0
            drop_rate = 0.0
        
        error_rates[iface] = {
            'error_rate_percent': round(error_rate, 3),
            'drop_rate_percent': round(drop_rate, 3),
            'total_errors': total_errors,
            'total_drops': total_drops,
            'total_packets': total_packets
        }
    
    return error_rates


def get_active_interface() -> Optional[str]:
    """Identify the most likely active network interface
    
    Returns:
        Name of the active interface, or None if not found
    """
    # Get default gateway interface
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default', {})
    
    if netifaces.AF_INET in default_gateway:
        return default_gateway[netifaces.AF_INET][1]
    
    # Fallback: Find interface with most traffic
    io_stats = get_interface_io_stats()
    max_traffic = 0
    active_interface = None
    
    for iface, stats in io_stats.items():
        if iface.startswith('lo'):  # Skip loopback
            continue
        
        total_traffic = stats['bytes_sent'] + stats['bytes_recv']
        if total_traffic > max_traffic:
            max_traffic = total_traffic
            active_interface = iface
    
    return active_interface


def get_network_utilization_summary() -> Dict[str, Any]:
    """Get a comprehensive summary of network utilization
    
    Returns:
        Dict with overall network statistics and per-interface breakdown
    """
    summary = {
        'timestamp': datetime.now().isoformat(),
        'active_interface': get_active_interface(),
        'total_interfaces': len(get_all_interfaces()),
        'interfaces': {}
    }
    
    # Get bandwidth usage
    bandwidth = calculate_bandwidth_usage(interval=1.0)
    
    # Get error rates
    error_rates = get_interface_error_rates()
    
    # Get I/O stats
    io_stats = get_interface_io_stats()
    
    # Combine all data
    for iface in get_all_interfaces():
        if iface.startswith('lo'):  # Skip loopback
            continue
            
        interface_data = get_interface_details(iface)
        
        if iface in bandwidth:
            interface_data['bandwidth'] = bandwidth[iface]
        
        if iface in error_rates:
            interface_data['error_rates'] = error_rates[iface]
        
        if iface in io_stats:
            interface_data['io_stats'] = io_stats[iface]
        
        summary['interfaces'][iface] = interface_data
    
    # Calculate totals
    total_upload = sum(bw.get('upload_mbps', 0) for bw in bandwidth.values())
    total_download = sum(bw.get('download_mbps', 0) for bw in bandwidth.values())
    
    summary['total_bandwidth'] = {
        'upload_mbps': round(total_upload, 2),
        'download_mbps': round(total_download, 2),
        'total_mbps': round(total_upload + total_download, 2)
    }
    
    return summary


# Standalone callable functions for Claude Code integration

def check_interface_health(interface: str) -> Dict[str, Any]:
    """Quick health check for a specific interface
    
    This function is designed to be called by Claude Code when diagnosing
    interface-specific issues.
    
    Args:
        interface: Network interface name
        
    Returns:
        Dict with health status and any issues found
    """
    health = {
        'interface': interface,
        'status': 'unknown',
        'issues': [],
        'metrics': {}
    }
    
    # Get interface details
    details = get_interface_details(interface)
    
    if not details['exists']:
        health['status'] = 'not_found'
        health['issues'].append('Interface does not exist')
        return health
    
    if not details['is_up']:
        health['status'] = 'down'
        health['issues'].append('Interface is down')
        return health
    
    # Check error rates
    error_rates = get_interface_error_rates(interface)
    if interface in error_rates:
        error_rate = error_rates[interface]['error_rate_percent']
        drop_rate = error_rates[interface]['drop_rate_percent']
        
        health['metrics']['error_rate'] = error_rate
        health['metrics']['drop_rate'] = drop_rate
        
        if error_rate > 5:
            health['issues'].append(f'High error rate: {error_rate}%')
        elif error_rate > 1:
            health['issues'].append(f'Elevated error rate: {error_rate}%')
        
        if drop_rate > 1:
            health['issues'].append(f'Packet drops detected: {drop_rate}%')
    
    # Check bandwidth
    bandwidth = calculate_bandwidth_usage(interval=1.0, interface=interface)
    if interface in bandwidth:
        health['metrics']['bandwidth'] = bandwidth[interface]
    
    # Determine overall status
    if health['issues']:
        health['status'] = 'warning'
    else:
        health['status'] = 'healthy'
    
    return health


def monitor_bandwidth_realtime(duration: int = 60, interval: int = 5) -> List[Dict[str, Any]]:
    """Monitor bandwidth usage in real-time for a specified duration
    
    This function is useful for Claude Code when troubleshooting
    intermittent bandwidth issues.
    
    Args:
        duration: Total monitoring duration in seconds
        interval: Sampling interval in seconds
        
    Returns:
        List of bandwidth measurements over time
    """
    measurements = []
    start_time = time.time()
    
    while time.time() - start_time < duration:
        measurement = {
            'timestamp': datetime.now().isoformat(),
            'elapsed_seconds': round(time.time() - start_time, 1),
            'bandwidth': calculate_bandwidth_usage(interval=interval)
        }
        measurements.append(measurement)
        
        # Print real-time update (useful for interactive sessions)
        active_iface = get_active_interface()
        if active_iface and active_iface in measurement['bandwidth']:
            bw = measurement['bandwidth'][active_iface]
            print(f"[{measurement['elapsed_seconds']}s] {active_iface}: "
                  f"↑{bw['upload_mbps']} Mbps ↓{bw['download_mbps']} Mbps")
    
    return measurements


if __name__ == "__main__":
    # Demo the network metrics capabilities
    print("🌐 NETWORK INTERFACE METRICS")
    print("=" * 50)
    
    # Show all interfaces
    print("\n📋 Available Interfaces:")
    for iface in get_all_interfaces():
        details = get_interface_details(iface)
        status = "UP" if details['is_up'] else "DOWN"
        print(f"  • {iface}: {status}")
    
    # Show active interface metrics
    active = get_active_interface()
    if active:
        print(f"\n🔍 Active Interface: {active}")
        health = check_interface_health(active)
        print(f"   Status: {health['status']}")
        if health['issues']:
            print("   Issues:")
            for issue in health['issues']:
                print(f"     - {issue}")
        
        print("\n📊 Real-time Bandwidth (5 second sample):")
        monitor_bandwidth_realtime(duration=5, interval=1)
    
    # Show summary
    print("\n📈 Network Utilization Summary:")
    summary = get_network_utilization_summary()
    print(f"   Total Bandwidth: ↑{summary['total_bandwidth']['upload_mbps']} Mbps "
          f"↓{summary['total_bandwidth']['download_mbps']} Mbps")