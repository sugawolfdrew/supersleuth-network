#!/usr/bin/env python3
"""
Port Scanner Demo Script
Demonstrates how Claude Code would use the Port Connectivity Scanner module
to diagnose common network issues.
"""

import sys
import os
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics.port_scanner import (
    check_single_port,
    scan_port_range,
    scan_common_services,
    bulk_host_scan,
    test_service_chain,
    measure_connection_stability,
    diagnose_website_down,
    diagnose_email_issues,
    diagnose_database_connection,
    perform_health_check,
    PortScanner
)


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}\n")


def demo_website_down():
    """Demo: Diagnose why a website is not accessible"""
    print_section("Scenario 1: Website is Down")
    
    print("User reports: 'Our company website is not loading'")
    print("\nClaude Code investigates using port scanner...\n")
    
    # Example diagnosis
    results = diagnose_website_down("example.com")
    
    print(f"Target: {results['host']}")
    print(f"\nHTTP (Port 80): {'OPEN' if results['http']['open'] else 'CLOSED'}")
    if results['http']['latency']:
        print(f"  Latency: {results['http']['latency']}ms")
    
    print(f"\nHTTPS (Port 443): {'OPEN' if results['https']['open'] else 'CLOSED'}")
    if results['https']['latency']:
        print(f"  Latency: {results['https']['latency']}ms")
    
    print("\nDiagnosis:")
    for diag in results['diagnosis']:
        print(f"  - {diag}")
    
    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"  • {rec}")


def demo_email_not_working():
    """Demo: Diagnose email connectivity issues"""
    print_section("Scenario 2: Email Not Working")
    
    print("User reports: 'Cannot send or receive emails'")
    print("\nClaude Code checks email server connectivity...\n")
    
    # Example diagnosis
    results = diagnose_email_issues("mail.example.com", "both")
    
    print(f"Mail Server: {results['mail_server']}")
    print("\nService Status:")
    
    for service, result in results['services'].items():
        status = 'OPEN' if result['open'] else 'CLOSED'
        print(f"  {service}: {status}")
        if result['open'] and result['latency']:
            print(f"    Latency: {result['latency']}ms")
    
    print("\nDiagnosis:")
    for diag in results['diagnosis']:
        print(f"  - {diag}")
    
    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"  • {rec}")


def demo_database_connection():
    """Demo: Diagnose database connectivity issues"""
    print_section("Scenario 3: Can't Connect to Database")
    
    print("Developer reports: 'Application cannot connect to MySQL database'")
    print("\nClaude Code tests database connectivity...\n")
    
    # Example diagnosis
    results = diagnose_database_connection("db.internal.local", "mysql")
    
    print(f"Database Host: {results['db_host']}")
    
    for db_type, result in results['databases'].items():
        print(f"\n{db_type.upper()} (Port {result['port']}):")
        print(f"  Status: {'OPEN' if result['open'] else 'CLOSED'}")
        if result['open'] and result['latency']:
            print(f"  Latency: {result['latency']}ms")
        if result['error']:
            print(f"  Error: {result['error']}")
    
    print("\nDiagnosis:")
    for diag in results['diagnosis']:
        print(f"  - {diag}")
    
    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"  • {rec}")


def demo_service_health_check():
    """Demo: Comprehensive service health check"""
    print_section("Scenario 4: Service Health Check")
    
    print("Admin requests: 'Check if all critical services are running'")
    print("\nClaude Code performs comprehensive health check...\n")
    
    # Define services to check
    services = [
        {'name': 'Web Server', 'host': 'www.example.com', 'port': 443, 'critical': True},
        {'name': 'API Server', 'host': 'api.example.com', 'port': 8080, 'critical': True},
        {'name': 'Database', 'host': 'db.example.com', 'port': 5432, 'critical': True},
        {'name': 'Cache Server', 'host': 'cache.example.com', 'port': 6379, 'critical': False},
        {'name': 'Mail Server', 'host': 'mail.example.com', 'port': 587, 'critical': False}
    ]
    
    results = perform_health_check(services)
    
    print(f"Overall Status: {results['overall_status'].upper()}")
    print(f"Health Score: {results['health_score']}%")
    print(f"Total Latency: {results['total_latency']}ms")
    
    print("\nService Details:")
    for service in results['services']:
        status = '✓' if service['open'] else '✗'
        critical = ' [CRITICAL]' if any(
            s['name'] == service['name'] and s.get('critical', False) 
            for s in services
        ) else ''
        
        print(f"  {status} {service['name']}{critical}")
        if service['open'] and service['latency']:
            print(f"    Latency: {service['latency']}ms")
        if service['error']:
            print(f"    Error: {service['error']}")
    
    if results['failed_services']:
        print(f"\nFailed Services: {', '.join(results['failed_services'])}")
    
    if 'critical_failures' in results:
        print(f"\nCRITICAL FAILURES: {', '.join(results['critical_failures'])}")


def demo_stability_test():
    """Demo: Test connection stability over time"""
    print_section("Scenario 5: Intermittent Connection Issues")
    
    print("User reports: 'Website works sometimes but connection drops randomly'")
    print("\nClaude Code tests connection stability over 10 seconds...\n")
    
    # Test stability (shorter duration for demo)
    results = measure_connection_stability("example.com", 443, duration=5, interval=0.5)
    
    print(f"Target: {results['host']}:{results['port']}")
    print(f"Test Duration: {results['duration']} seconds")
    print(f"\nResults:")
    print(f"  Successful Connections: {results['successful_connections']}")
    print(f"  Failed Connections: {results['failed_connections']}")
    print(f"  Stability Score: {results['stability_score']}%")
    
    if results['average_latency']:
        print(f"\nLatency Statistics:")
        print(f"  Average: {results['average_latency']}ms")
        print(f"  Min: {results['min_latency']}ms")
        print(f"  Max: {results['max_latency']}ms")
        print(f"  Variance: {results.get('latency_variance', 0)}ms²")
    
    # Recommendations based on stability
    print("\nAnalysis:")
    if results['stability_score'] < 95:
        print("  - Connection is unstable")
        print("  - Investigate network path and intermediate devices")
        print("  - Check for packet loss or network congestion")
    else:
        print("  - Connection is stable")
        if results.get('latency_variance', 0) > 50:
            print("  - High latency variance detected")
            print("  - May indicate network congestion")


def demo_port_range_scan():
    """Demo: Scan a range of ports"""
    print_section("Advanced: Port Range Scan")
    
    print("Security audit: 'Check what ports are open on the server'")
    print("\nClaude Code scans common ports...\n")
    
    # Scan common privileged ports
    results = scan_port_range("localhost", 20, 25, timeout=1.0)
    
    print("Open ports found:")
    if results:
        for port_info in results:
            print(f"  Port {port_info['port']}: {port_info['service']}")
            if port_info['latency']:
                print(f"    Latency: {port_info['latency']}ms")
    else:
        print("  No open ports in range 20-25")


def demo_bulk_scan():
    """Demo: Scan multiple hosts"""
    print_section("Advanced: Multi-Host Scan")
    
    print("Network admin: 'Check if web servers are responding'")
    print("\nClaude Code checks multiple servers...\n")
    
    # Check multiple hosts
    hosts = ["example.com", "google.com", "localhost"]
    ports = [80, 443]
    
    results = bulk_host_scan(hosts, ports, timeout=2.0)
    
    for host, scan_results in results.items():
        print(f"{host}:")
        for result in scan_results:
            status = 'OPEN' if result['open'] else 'CLOSED'
            print(f"  Port {result['port']} ({result['service']}): {status}")
            if result['open'] and result['latency']:
                print(f"    Latency: {result['latency']}ms")
        print()


def demo_diagnostic_class():
    """Demo: Using the PortScanner diagnostic class"""
    print_section("Using PortScanner Diagnostic Class")
    
    print("Running comprehensive port scanner diagnostic...")
    
    # Configure and run diagnostic
    config = {
        'client_name': 'Demo Client',
        'target': 'example.com',
        'scan_type': 'common'
    }
    
    scanner = PortScanner(config)
    
    # Check authorization requirements
    auth_req = scanner.get_authorization_required()
    print(f"\nAuthorization Requirements:")
    print(f"  Risk Level: {auth_req['risk_level']}")
    print(f"  Description: {auth_req['description']}")
    
    # Run diagnostic
    print("\nExecuting diagnostic...")
    result = scanner.run()
    
    # Display results
    result_dict = result.to_dict()
    print(f"\nStatus: {result_dict['status']}")
    
    if result_dict['warnings']:
        print("\nWarnings:")
        for warning in result_dict['warnings']:
            print(f"  ⚠ {warning}")
    
    if result_dict['recommendations']:
        print("\nRecommendations:")
        for rec in result_dict['recommendations']:
            print(f"  • {rec}")


def main():
    """Run all demos"""
    print("\n" + "="*60)
    print(" Port Scanner Module Demo")
    print(" Demonstrating Claude Code Network Diagnostics")
    print("="*60)
    
    demos = [
        ("Website Down", demo_website_down),
        ("Email Issues", demo_email_not_working),
        ("Database Connection", demo_database_connection),
        ("Service Health Check", demo_service_health_check),
        ("Connection Stability", demo_stability_test),
        ("Port Range Scan", demo_port_range_scan),
        ("Multi-Host Scan", demo_bulk_scan),
        ("Diagnostic Class", demo_diagnostic_class)
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  0. Run all demos")
    
    try:
        choice = input("\nSelect demo (0-8): ").strip()
        
        if choice == '0':
            # Run all demos
            for name, demo_func in demos:
                try:
                    demo_func()
                    input("\nPress Enter to continue...")
                except Exception as e:
                    print(f"\nError in {name} demo: {e}")
        elif choice.isdigit() and 1 <= int(choice) <= len(demos):
            # Run selected demo
            demos[int(choice)-1][1]()
        else:
            print("Invalid choice")
    
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\nError running demo: {e}")
    
    print("\n" + "="*60)
    print(" Demo Complete")
    print("="*60)


if __name__ == "__main__":
    main()