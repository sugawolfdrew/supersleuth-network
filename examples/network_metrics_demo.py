#!/usr/bin/env python3
"""
Network Metrics Demo - How Claude Code would use the network metrics tools

This demonstrates how Claude Code can use the modular network metrics
functions to diagnose various network issues.
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.network_metrics import (
    get_all_interfaces,
    get_active_interface,
    check_interface_health,
    monitor_bandwidth_realtime,
    get_network_utilization_summary
)
from src.core.monitoring import NetworkMonitor


def scenario_1_slow_network():
    """IT Professional: 'The network feels slow today'"""
    
    print("\n🔍 SCENARIO 1: Diagnosing Slow Network")
    print("=" * 50)
    print("IT Professional: 'The network feels slow today'\n")
    
    print("Claude Code: Let me check your network interfaces and bandwidth usage...\n")
    
    # First, identify the active interface
    active = get_active_interface()
    print(f"✓ Active interface identified: {active}")
    
    # Check interface health
    health = check_interface_health(active)
    print(f"✓ Interface status: {health['status']}")
    
    if health['issues']:
        print("⚠️  Issues found:")
        for issue in health['issues']:
            print(f"   - {issue}")
    
    # Monitor bandwidth for a few seconds
    print("\n📊 Monitoring bandwidth usage (5 seconds)...")
    measurements = monitor_bandwidth_realtime(duration=5, interval=1)
    
    # Analyze results
    print("\nClaude Code: Based on my analysis:")
    if health['status'] == 'healthy':
        print("- Your network interface is healthy")
        print("- Current bandwidth usage is normal")
        print("- The slowness might be due to external factors (ISP, remote servers)")
    else:
        print("- I found some issues with your network interface")
        print("- This could be contributing to the slow performance")
        print("- Let me create a more detailed diagnostic...")


def scenario_2_intermittent_drops():
    """IT Professional: 'We keep losing connection every few minutes'"""
    
    print("\n\n🔍 SCENARIO 2: Intermittent Connection Drops")
    print("=" * 50)
    print("IT Professional: 'We keep losing connection every few minutes'\n")
    
    print("Claude Code: I'll monitor your network interfaces for errors and drops...\n")
    
    # Get all interfaces
    interfaces = get_all_interfaces()
    
    # Check each interface for errors
    problematic_interfaces = []
    
    for iface in interfaces:
        if iface.startswith('lo'):  # Skip loopback
            continue
            
        health = check_interface_health(iface)
        if health['status'] != 'healthy' and health['issues']:
            problematic_interfaces.append((iface, health))
    
    if problematic_interfaces:
        print("⚠️  Found interfaces with issues:")
        for iface, health in problematic_interfaces:
            print(f"\n   Interface: {iface}")
            for issue in health['issues']:
                print(f"   - {issue}")
            if 'error_rate' in health['metrics']:
                print(f"   - Error rate: {health['metrics']['error_rate']}%")
    else:
        print("✓ All interfaces appear healthy")
        print("  The drops might be due to:")
        print("  - WiFi interference")
        print("  - Router/switch issues")
        print("  - ISP problems")


def scenario_3_bandwidth_monitoring():
    """IT Professional: 'Can you monitor our bandwidth usage?'"""
    
    print("\n\n🔍 SCENARIO 3: Bandwidth Usage Analysis")
    print("=" * 50)
    print("IT Professional: 'Can you monitor our bandwidth usage?'\n")
    
    print("Claude Code: I'll provide a comprehensive network utilization summary...\n")
    
    # Get network summary
    summary = get_network_utilization_summary()
    
    print(f"📊 Network Utilization Report")
    print(f"   Time: {summary['timestamp']}")
    print(f"   Active Interface: {summary['active_interface']}")
    print(f"   Total Interfaces: {summary['total_interfaces']}")
    print(f"\n   Overall Bandwidth:")
    print(f"   - Upload: {summary['total_bandwidth']['upload_mbps']} Mbps")
    print(f"   - Download: {summary['total_bandwidth']['download_mbps']} Mbps")
    
    # Show top bandwidth consumers
    print("\n   Top Bandwidth Consumers:")
    interfaces_by_bandwidth = sorted(
        [(iface, data.get('bandwidth', {}).get('total_mbps', 0)) 
         for iface, data in summary['interfaces'].items()],
        key=lambda x: x[1],
        reverse=True
    )
    
    for iface, bandwidth in interfaces_by_bandwidth[:3]:
        if bandwidth > 0:
            print(f"   - {iface}: {bandwidth} Mbps")


def integration_with_monitoring():
    """Show how to use the NetworkMonitor integration"""
    
    print("\n\n🔧 INTEGRATION: Using NetworkMonitor")
    print("=" * 50)
    print("Demonstrating modular network metrics via NetworkMonitor...\n")
    
    # Create a monitor instance
    monitor = NetworkMonitor({'client_name': 'Demo'}, check_interval=5)
    
    # Get network metrics for all interfaces
    all_metrics = monitor.get_network_metrics()
    print(f"✓ Retrieved metrics for {all_metrics['total_interfaces']} interfaces")
    
    # Get metrics for specific interface
    active = get_active_interface()
    if active:
        specific_metrics = monitor.get_network_metrics(active)
        print(f"\n📊 Metrics for {active}:")
        if 'bandwidth' in specific_metrics:
            print(f"   Bandwidth: {specific_metrics['bandwidth'].get('total_mbps', 0)} Mbps")
        if 'error_rates' in specific_metrics:
            print(f"   Error Rate: {specific_metrics['error_rates'].get('error_rate_percent', 0)}%")


if __name__ == "__main__":
    print("🌐 NETWORK METRICS TOOLKIT DEMO")
    print("Showing how Claude Code would use these tools")
    
    # Run scenarios
    scenario_1_slow_network()
    scenario_2_intermittent_drops()
    scenario_3_bandwidth_monitoring()
    integration_with_monitoring()
    
    print("\n\n✨ These modular functions can be combined and customized")
    print("   by Claude Code based on the specific network issue!")