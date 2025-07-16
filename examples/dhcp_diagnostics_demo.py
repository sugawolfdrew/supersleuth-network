#!/usr/bin/env python3
"""
DHCP Diagnostics Demo for SuperSleuth Network

This script demonstrates how Claude Code would use the DHCP diagnostics
module to troubleshoot common DHCP-related network issues.
"""

import sys
import json
import time
from datetime import datetime

# Add src to path
sys.path.insert(0, '../src')

from diagnostics.dhcp_diagnostics import (
    discover_dhcp_servers,
    check_ip_conflicts,
    get_lease_info,
    find_rogue_dhcp_servers,
    test_dhcp_renewal,
    diagnose_dhcp_issue,
    DHCPDiagnostics
)


def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print(f"{'=' * 60}")


def print_json(data):
    """Pretty print JSON data"""
    print(json.dumps(data, indent=2, default=str))


def demo_cant_get_ip():
    """Demo: User can't get an IP address"""
    print_section("SCENARIO 1: Can't Get IP Address")
    print("User reports: 'My computer won't connect to the network'")
    print("\nClaude Code investigates...")
    
    # Run comprehensive diagnosis
    diagnosis = diagnose_dhcp_issue('no_ip')
    
    print("\n1. Checking for DHCP servers on the network...")
    servers = diagnosis['findings'].get('dhcp_servers', [])
    if servers:
        print(f"   Found {len(servers)} DHCP server(s):")
        for server in servers:
            if 'error' not in server:
                print(f"   - Server: {server.get('server_ip')}")
                print(f"     Offering IP: {server.get('offered_ip')}")
    else:
        print("   No DHCP servers found!")
    
    print("\n2. Checking current lease status...")
    lease = diagnosis['findings'].get('current_lease', {})
    print(f"   Current IP: {lease.get('current_ip', 'None')}")
    print(f"   Lease Status: {lease.get('status', 'Unknown')}")
    print(f"   DHCP Server: {lease.get('dhcp_server', 'None')}")
    
    print("\n3. Recommendations:")
    for rec in diagnosis['recommendations']:
        print(f"   - {rec}")
    
    # Show the raw data for debugging
    if '--verbose' in sys.argv:
        print("\nRaw diagnosis data:")
        print_json(diagnosis)


def demo_ip_conflict():
    """Demo: IP conflict detected"""
    print_section("SCENARIO 2: IP Conflict Detected")
    print("User reports: 'I keep getting IP conflict warnings'")
    print("\nClaude Code investigates...")
    
    # Check for conflicts
    print("\n1. Scanning for IP conflicts...")
    conflicts = check_ip_conflicts()
    
    if conflicts:
        print(f"   Found {len(conflicts)} conflict(s):")
        for conflict in conflicts:
            if 'error' not in conflict:
                print(f"   - IP: {conflict.get('ip_address')}")
                print(f"     Conflicting MACs: {conflict.get('conflicting_macs', [])}")
                print(f"     Severity: {conflict.get('severity')}")
    else:
        print("   No conflicts detected")
    
    # Get current lease info
    print("\n2. Current DHCP lease information:")
    lease = get_lease_info()
    print(f"   Your IP: {lease.get('current_ip')}")
    print(f"   DHCP Server: {lease.get('dhcp_server')}")
    print(f"   Lease Status: {lease.get('status')}")
    
    # Run full diagnosis
    diagnosis = diagnose_dhcp_issue('conflict')
    
    print("\n3. Recommendations:")
    for rec in diagnosis['recommendations']:
        print(f"   - {rec}")
    
    if '--verbose' in sys.argv:
        print("\nRaw conflict data:")
        print_json(conflicts)


def demo_renewal_issues():
    """Demo: Network issues after lease renewal"""
    print_section("SCENARIO 3: Network Issues After Lease Renewal")
    print("User reports: 'Internet stops working every few hours'")
    print("\nClaude Code investigates...")
    
    # Check current lease
    print("\n1. Analyzing current DHCP lease...")
    lease = get_lease_info()
    print(f"   Current IP: {lease.get('current_ip')}")
    print(f"   Lease Status: {lease.get('status')}")
    print(f"   Time Remaining: {lease.get('lease_time_remaining', 'Unknown')}")
    
    if lease.get('status') == 'expiring_soon':
        print("   WARNING: Lease expiring soon!")
    
    # Test renewal
    print("\n2. Testing DHCP lease renewal process...")
    print("   (This may take a few seconds)")
    
    renewal_result = test_dhcp_renewal()
    
    print(f"\n   Renewal attempted: {renewal_result['renewal_attempted']}")
    print(f"   Renewal successful: {renewal_result['renewal_successful']}")
    
    if renewal_result['renewal_successful']:
        old_ip = renewal_result['current_lease'].get('current_ip')
        new_ip = renewal_result['new_lease'].get('current_ip')
        
        if old_ip != new_ip:
            print(f"   WARNING: IP changed from {old_ip} to {new_ip}")
        
        if renewal_result.get('warnings'):
            print("   Warnings:")
            for warning in renewal_result['warnings']:
                print(f"   - {warning}")
    else:
        print("   ERROR: Lease renewal failed!")
        if renewal_result.get('errors'):
            for error in renewal_result['errors']:
                print(f"   - {error}")
    
    # Get recommendations
    diagnosis = diagnose_dhcp_issue('renewal')
    
    print("\n3. Recommendations:")
    for rec in diagnosis['recommendations']:
        print(f"   - {rec}")
    
    if '--verbose' in sys.argv:
        print("\nRaw renewal test data:")
        print_json(renewal_result)


def demo_rogue_dhcp():
    """Demo: Suspected rogue DHCP server"""
    print_section("SCENARIO 4: Suspected Rogue DHCP Server")
    print("User reports: 'Network admin says there might be a rogue DHCP server'")
    print("\nClaude Code investigates...")
    
    # Discover all DHCP servers
    print("\n1. Discovering all DHCP servers (extended scan)...")
    all_servers = discover_dhcp_servers(timeout=10)
    
    print(f"   Found {len(all_servers)} DHCP server(s):")
    for i, server in enumerate(all_servers):
        if 'error' not in server:
            print(f"\n   Server #{i+1}:")
            print(f"   - IP: {server.get('server_ip')}")
            print(f"   - Server ID: {server.get('server_id')}")
            print(f"   - Offering: {server.get('offered_ip')}")
            print(f"   - Gateway: {server.get('gateway')}")
            print(f"   - DNS: {server.get('dns_servers', [])}")
    
    # Check for rogues
    print("\n2. Checking for rogue DHCP servers...")
    
    # Get authorized server from current lease
    current_lease = get_lease_info()
    authorized = [current_lease['dhcp_server']] if current_lease.get('dhcp_server') else None
    
    if authorized:
        print(f"   Authorized DHCP server: {authorized[0]}")
    
    rogue_servers = find_rogue_dhcp_servers(authorized)
    
    if rogue_servers:
        print(f"\n   ALERT: Found {len(rogue_servers)} potential rogue server(s)!")
        for rogue in rogue_servers:
            if rogue.get('type') == 'configuration_mismatch':
                print(f"   - Configuration mismatch detected!")
                print(f"     {rogue.get('details')}")
            else:
                print(f"   - Rogue server at {rogue.get('server_ip')}")
                print(f"     Severity: {rogue.get('severity')}")
    else:
        print("   No rogue servers detected")
    
    # Get recommendations
    diagnosis = diagnose_dhcp_issue('rogue')
    
    print("\n3. Recommendations:")
    for rec in diagnosis['recommendations']:
        print(f"   - {rec}")
    
    if '--verbose' in sys.argv:
        print("\nRaw rogue server data:")
        print_json(rogue_servers)


def demo_general_health():
    """Demo: General DHCP health check"""
    print_section("GENERAL DHCP HEALTH CHECK")
    print("Running comprehensive DHCP diagnostics...")
    
    # Create diagnostics instance
    diag = DHCPDiagnostics()
    
    # Run all checks
    print("\n1. DHCP Lease Information:")
    lease = diag.analyze_dhcp_lease()
    print(f"   Current IP: {lease.get('current_ip', 'None')}")
    print(f"   DHCP Server: {lease.get('dhcp_server', 'None')}")
    print(f"   Gateway: {lease.get('gateway', 'None')}")
    print(f"   DNS Servers: {', '.join(lease.get('dns_servers', [])) or 'None'}")
    print(f"   Lease Status: {lease.get('status', 'Unknown')}")
    
    if lease.get('lease_time_remaining'):
        print(f"   Time Remaining: {lease['lease_time_remaining']}")
    
    print("\n2. DHCP Server Discovery:")
    servers = diag.discover_dhcp_servers(timeout=3)
    print(f"   Found {len(servers)} DHCP server(s)")
    
    print("\n3. IP Conflict Check:")
    conflicts = diag.detect_ip_conflicts()
    if conflicts and not any('error' in c for c in conflicts):
        print(f"   WARNING: {len(conflicts)} conflict(s) detected!")
    else:
        print("   No conflicts detected")
    
    print("\n4. Overall Assessment:")
    diagnosis = diagnose_dhcp_issue('general')
    for rec in diagnosis['recommendations']:
        print(f"   - {rec}")
    
    if '--verbose' in sys.argv:
        print("\nDetailed health check data:")
        print_json({
            'lease': lease,
            'servers': servers,
            'conflicts': conflicts,
            'diagnosis': diagnosis
        })


def interactive_mode():
    """Interactive diagnostic mode"""
    print_section("INTERACTIVE DHCP DIAGNOSTICS")
    print("\nSelect a diagnostic scenario:")
    print("1. Can't get IP address")
    print("2. IP conflict detected")
    print("3. Network issues after lease renewal")
    print("4. Suspected rogue DHCP server")
    print("5. General health check")
    print("6. Exit")
    
    while True:
        try:
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == '1':
                demo_cant_get_ip()
            elif choice == '2':
                demo_ip_conflict()
            elif choice == '3':
                demo_renewal_issues()
            elif choice == '4':
                demo_rogue_dhcp()
            elif choice == '5':
                demo_general_health()
            elif choice == '6':
                print("\nExiting...")
                break
            else:
                print("Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {e}")


def main():
    """Main demo function"""
    print("SuperSleuth Network - DHCP Diagnostics Demo")
    print("=" * 60)
    print("\nThis demo shows how Claude Code would use DHCP diagnostics")
    print("to troubleshoot common network issues.")
    
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        interactive_mode()
    else:
        # Run all demos
        print("\nRunning all diagnostic scenarios...")
        print("(Use --interactive for interactive mode)")
        print("(Use --verbose for detailed output)")
        
        time.sleep(2)
        
        # Run each scenario
        demo_cant_get_ip()
        time.sleep(1)
        
        demo_ip_conflict()
        time.sleep(1)
        
        demo_renewal_issues()
        time.sleep(1)
        
        demo_rogue_dhcp()
        time.sleep(1)
        
        demo_general_health()
        
        print("\n" + "=" * 60)
        print("Demo complete!")
        print("\nUsage tips for Claude Code:")
        print("- Import specific functions as needed")
        print("- Use diagnose_dhcp_issue() for comprehensive analysis")
        print("- All functions return structured data for easy parsing")
        print("- Handle errors gracefully - network operations may fail")


if __name__ == "__main__":
    main()