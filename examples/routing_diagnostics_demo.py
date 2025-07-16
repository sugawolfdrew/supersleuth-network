#!/usr/bin/env python3
"""
Routing Diagnostics Demo
Demonstrates how Claude Code would use routing diagnostic tools
to troubleshoot common network routing issues
"""

import json
import time
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics.routing_diagnostics import (
    RoutingDiagnostics,
    analyze_routes,
    check_gateway,
    trace_route,
    discover_mtu,
    monitor_route,
    check_asymmetric_routing
)


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def scenario_cant_reach_remote_network():
    """Scenario: User reports 'Can't reach remote network'"""
    print_section("SCENARIO: Can't reach remote network")
    print("\nUser reports: 'I can access local resources but can't reach external websites'")
    print("\nClaude Code's diagnostic approach:")
    
    # Step 1: Check default gateway
    print("\n1. Checking default gateway health...")
    gateway_result = check_gateway()
    
    if gateway_result.get('reachable'):
        print(f"   ✓ Gateway {gateway_result['gateway_ip']} is reachable")
        print(f"   - Status: {gateway_result['status']}")
        print(f"   - Packet loss: {gateway_result['packet_loss']}%")
        print(f"   - Average RTT: {gateway_result.get('avg_rtt', 'N/A')}ms")
    else:
        print(f"   ✗ Gateway is not reachable!")
        print("   RECOMMENDATION: Check local network connection and gateway device")
        return
    
    # Step 2: Analyze routing table
    print("\n2. Analyzing routing table...")
    routes = analyze_routes()
    
    print(f"   - Total routes: {routes['route_count']}")
    if routes.get('potential_issues'):
        print("   - Potential issues found:")
        for issue in routes['potential_issues']:
            print(f"     • {issue}")
    else:
        print("   - No routing table issues detected")
    
    # Step 3: Trace route to external target
    print("\n3. Tracing route to 8.8.8.8 (Google DNS)...")
    trace_result = trace_route("8.8.8.8", max_hops=15)
    
    if 'error' not in trace_result:
        analysis = trace_result.get('analysis', {})
        print(f"   - Hops to target: {analysis.get('total_hops', 'Unknown')}")
        print(f"   - Unreachable hops: {analysis.get('unreachable_hops', 0)}")
        
        if analysis.get('high_latency_hops'):
            print("   - High latency detected at:")
            for hop in analysis['high_latency_hops'][:3]:
                print(f"     • Hop {hop['hop']}: {hop['avg_rtt']}ms")
                
        if analysis.get('potential_issues'):
            print("   - Issues detected:")
            for issue in analysis['potential_issues']:
                print(f"     • {issue}")
    else:
        print(f"   ✗ Traceroute failed: {trace_result['error']}")
    
    # Step 4: Check MTU
    print("\n4. Checking Path MTU...")
    mtu_result = discover_mtu("8.8.8.8")
    
    if 'error' not in mtu_result:
        print(f"   - Discovered MTU: {mtu_result['discovered_mtu']} ({mtu_result['mtu_type']})")
        if mtu_result['discovered_mtu'] < 1500:
            print(f"   - MTU is {mtu_result['mtu_difference']} bytes below standard Ethernet")
            print("   - This may cause fragmentation and performance issues")
    
    print("\n[Claude Code would continue with specific recommendations based on findings]")


def scenario_intermittent_drops():
    """Scenario: Intermittent connection drops"""
    print_section("SCENARIO: Intermittent connection drops")
    print("\nUser reports: 'My connection keeps dropping randomly'")
    print("\nClaude Code's diagnostic approach:")
    
    # Monitor route stability
    print("\n1. Monitoring route stability for 30 seconds...")
    print("   (In real scenario, this would run longer)")
    
    # Simulate shorter duration for demo
    stability_result = monitor_route("8.8.8.8", duration=10, interval=2)
    
    if 'error' not in stability_result:
        print(f"   - Monitoring complete: {stability_result['checks_performed']} checks")
        print(f"   - Route changes detected: {stability_result['route_changes']}")
        print(f"   - Stability: {stability_result['stability_percentage']:.1f}%")
        print(f"   - Assessment: {stability_result['assessment']}")
        
        if stability_result['route_changes'] > 0:
            print("\n   Route changes detected:")
            for change in stability_result['changes']:
                print(f"   • {change['timestamp']}: Route changed")
    
    # Check gateway stability
    print("\n2. Checking gateway stability with multiple pings...")
    gateway_result = check_gateway()
    
    if gateway_result.get('packet_loss', 0) > 0:
        print(f"   ⚠ Packet loss to gateway: {gateway_result['packet_loss']}%")
        print("   - This indicates local network instability")
    
    print("\n[Claude Code would recommend checking physical connections, WiFi signal, etc.]")


def scenario_slow_performance():
    """Scenario: Slow network performance"""
    print_section("SCENARIO: Slow network performance")
    print("\nUser reports: 'Internet is very slow'")
    print("\nClaude Code's diagnostic approach:")
    
    # Check for routing issues
    print("\n1. Analyzing route path for latency issues...")
    trace_result = trace_route("www.google.com", max_hops=20)
    
    if 'error' not in trace_result:
        analysis = trace_result.get('analysis', {})
        high_latency_hops = analysis.get('high_latency_hops', [])
        
        if high_latency_hops:
            print(f"   ⚠ Found {len(high_latency_hops)} hops with high latency (>100ms):")
            for hop in high_latency_hops[:5]:
                print(f"     • Hop {hop['hop']}: {hop['avg_rtt']}ms ({hop.get('ip', 'Unknown')})")
        else:
            print("   ✓ No high latency hops detected")
    
    # Check MTU issues
    print("\n2. Checking for MTU-related performance issues...")
    mtu_result = discover_mtu("www.google.com")
    
    if 'error' not in mtu_result:
        if mtu_result['discovered_mtu'] < 1400:
            print(f"   ⚠ Low MTU detected: {mtu_result['discovered_mtu']}")
            print("   - This can significantly impact performance")
            print("   - Recommendation: Check VPN/tunnel configurations")
        else:
            print(f"   ✓ MTU is acceptable: {mtu_result['discovered_mtu']}")
    
    # Check for asymmetric routing
    print("\n3. Checking for asymmetric routing...")
    asymmetric_result = check_asymmetric_routing("8.8.8.8")
    
    if 'error' not in asymmetric_result:
        notes = asymmetric_result.get('analysis', {}).get('notes', [])
        if notes:
            print("   ⚠ Potential routing complexity detected:")
            for note in notes:
                print(f"     • {note}")
    
    print("\n[Claude Code would provide performance optimization recommendations]")


def scenario_routing_loop():
    """Scenario: Suspected routing loop"""
    print_section("SCENARIO: Routing loops suspected")
    print("\nUser reports: 'Connections time out, suspect routing loop'")
    print("\nClaude Code's diagnostic approach:")
    
    # Analyze routing table for issues
    print("\n1. Checking routing table for conflicts...")
    routes = analyze_routes()
    
    if routes.get('potential_issues'):
        print("   ⚠ Routing table issues detected:")
        for issue in routes['potential_issues']:
            print(f"     • {issue}")
    
    # Trace route looking for loops
    print("\n2. Tracing route to detect loops...")
    trace_result = trace_route("8.8.8.8", max_hops=30)
    
    if 'error' not in trace_result:
        hops = trace_result.get('hops', [])
        
        # Check for duplicate IPs (indicating loop)
        seen_ips = {}
        loop_detected = False
        
        for hop in hops:
            if hop.get('ip'):
                if hop['ip'] in seen_ips:
                    print(f"   ⚠ LOOP DETECTED: IP {hop['ip']} appears at hops {seen_ips[hop['ip']]} and {hop['hop']}")
                    loop_detected = True
                else:
                    seen_ips[hop['ip']] = hop['hop']
        
        if not loop_detected:
            print("   ✓ No routing loops detected in path")
    
    print("\n[Claude Code would analyze specific loop patterns and suggest fixes]")


def scenario_gateway_not_responding():
    """Scenario: Gateway not responding"""
    print_section("SCENARIO: Gateway not responding")
    print("\nUser reports: 'No internet access, gateway might be down'")
    print("\nClaude Code's diagnostic approach:")
    
    # Create diagnostic instance
    diag = RoutingDiagnostics()
    
    # Step 1: Identify gateway
    print("\n1. Identifying default gateway...")
    gateway_info = diag.get_default_gateway()
    
    if gateway_info:
        print(f"   - Gateway IP: {gateway_info['gateway']}")
        print(f"   - Interface: {gateway_info['interface']}")
        print(f"   - Detection method: {gateway_info['method']}")
    else:
        print("   ✗ Could not determine default gateway!")
        print("   - Check network adapter configuration")
        return
    
    # Step 2: Test gateway connectivity
    print("\n2. Testing gateway connectivity...")
    gateway_health = check_gateway()
    
    if not gateway_health.get('reachable'):
        print(f"   ✗ Gateway {gateway_info['gateway']} is NOT responding")
        print("\n   Troubleshooting steps:")
        print("   1. Check physical network connection")
        print("   2. Verify IP configuration (ipconfig/ifconfig)")
        print("   3. Try manually pinging gateway")
        print("   4. Check if gateway device is powered on")
        print("   5. Contact network administrator")
    else:
        print(f"   ✓ Gateway is responding")
        print("   - The issue might be beyond the local gateway")
    
    # Step 3: Check local network
    print("\n3. Checking local network configuration...")
    routes = analyze_routes()
    
    # Look for any routes at all
    if routes['route_count'] == 0:
        print("   ✗ No routes found - network stack may need reset")
    elif routes['route_count'] < 3:
        print(f"   ⚠ Only {routes['route_count']} routes found - configuration may be incomplete")
    
    print("\n[Claude Code would provide specific recovery steps based on OS]")


def run_comprehensive_diagnostic():
    """Run a comprehensive routing diagnostic"""
    print_section("COMPREHENSIVE ROUTING DIAGNOSTIC")
    
    diag = RoutingDiagnostics()
    result = diag.run()
    
    print("\nDiagnostic Results:")
    print(json.dumps(result.to_dict(), indent=2))


def main():
    """Run all demo scenarios"""
    print("SuperSleuth Network - Routing Diagnostics Demo")
    print("=" * 60)
    print("\nThis demo shows how Claude Code would use routing diagnostics")
    print("to troubleshoot common network routing issues.\n")
    
    # Let user choose scenario
    scenarios = {
        '1': ("Can't reach remote network", scenario_cant_reach_remote_network),
        '2': ("Intermittent connection drops", scenario_intermittent_drops),
        '3': ("Slow network performance", scenario_slow_performance),
        '4': ("Routing loops suspected", scenario_routing_loop),
        '5': ("Gateway not responding", scenario_gateway_not_responding),
        '6': ("Run comprehensive diagnostic", run_comprehensive_diagnostic)
    }
    
    print("Available scenarios:")
    for key, (name, _) in scenarios.items():
        print(f"  {key}. {name}")
    
    print("\nWhich scenario would you like to see? (1-6, or 'all' for all scenarios): ", end='')
    
    try:
        choice = input().strip().lower()
        
        if choice == 'all':
            for name, func in scenarios.values():
                func()
                time.sleep(1)
        elif choice in scenarios:
            _, func = scenarios[choice]
            func()
        else:
            print("Invalid choice. Running scenario 1...")
            scenario_cant_reach_remote_network()
            
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\nError running demo: {e}")
        
    print("\n\nDemo complete!")


if __name__ == "__main__":
    main()