#!/usr/bin/env python3
"""
Network Scanning Demo - Claude Code Integration Example

This script demonstrates how Claude Code can orchestrate the network scanning
modules to perform comprehensive network diagnostics.
"""

import sys
import json
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, '../src')

from diagnostics.diagnostic_api import NetworkDiagnosticAPI, DiagnosticType
from diagnostics import service_detection, os_fingerprinting, script_scanning


def demonstrate_basic_scanning():
    """Demonstrate basic network scanning capabilities."""
    print("\n=== Basic Network Scanning Demo ===\n")
    
    # Initialize the API
    api = NetworkDiagnosticAPI()
    
    # Example target (localhost for safety)
    target = "127.0.0.1"
    
    print(f"Target: {target}")
    print("-" * 50)
    
    # 1. Port Scanning
    print("\n1. Port Scanning (common ports)")
    port_result = api.run_diagnostic(target, 'port_scan', ports='21-25,80,443,3306,5432,8080')
    print(f"   Scanned {port_result['ports_scanned']} ports")
    print(f"   Open ports: {len(port_result['open_ports'])}")
    for port_info in port_result['open_ports']:
        print(f"   - Port {port_info['port']}: {port_info['state']}")
    
    # 2. Service Detection
    print("\n2. Service Detection")
    if port_result['open_ports']:
        service_result = api.run_diagnostic(target, 'service_detection', 
                                          open_ports=port_result['open_ports'])
        print(f"   Detected {len(service_result['services'])} services:")
        for svc in service_result['services']:
            print(f"   - Port {svc['port']}: {svc['service']}")
            if svc.get('banner'):
                print(f"     Banner: {svc['banner'][:50]}...")
    
    # 3. OS Detection
    print("\n3. OS Detection")
    os_result = api.run_diagnostic(target, 'os_detection', 
                                 open_ports=port_result['open_ports'])
    print(f"   OS: {os_result['os']}")
    print(f"   OS Family: {os_result['os_family']}")
    print(f"   Confidence: {os_result['confidence']:.1%}")
    print(f"   Methods used: {', '.join(os_result['methods_used'])}")


def demonstrate_workflow():
    """Demonstrate diagnostic workflow capabilities."""
    print("\n=== Diagnostic Workflow Demo ===\n")
    
    api = NetworkDiagnosticAPI()
    target = "127.0.0.1"
    
    # Define a diagnostic workflow
    workflow = [
        {'type': 'port_scan', 'params': {'ports': '1-1000'}},
        {'type': 'service_detection', 'use_previous': 'open_ports'},
        {'type': 'os_detection', 'use_previous': 'open_ports'},
        {'type': 'vulnerability_scan', 'use_previous': 'services'}
    ]
    
    print(f"Running workflow on {target}:")
    print("1. Port scan (ports 1-1000)")
    print("2. Service detection on open ports")
    print("3. OS fingerprinting")
    print("4. Vulnerability scanning")
    print("-" * 50)
    
    # Run the workflow
    results = api.run_workflow(target, workflow)
    
    # Display summary
    summary = results['summary']
    print(f"\nWorkflow Summary:")
    print(f"- Total open ports: {summary['total_open_ports']}")
    print(f"- Detected services: {', '.join(summary['detected_services']) or 'None'}")
    print(f"- OS Detection: {summary['os_detection'] or 'Unknown'}")
    print(f"- Vulnerabilities found: {len(summary['vulnerabilities'])}")
    print(f"- Risk level: {summary['risk_level'].upper()}")


def demonstrate_intelligent_analysis():
    """Demonstrate intelligent target analysis."""
    print("\n=== Intelligent Analysis Demo ===\n")
    
    api = NetworkDiagnosticAPI()
    target = "scanme.nmap.org"  # Public test server
    
    print(f"Performing intelligent analysis of {target}")
    print("(Using public test server - safe to scan)")
    print("-" * 50)
    
    # Perform analysis
    analysis = api.analyze_target(target, analysis_depth='quick')
    
    # Display analysis results
    print("\nAnalysis Results:")
    print(f"Security Posture: {analysis['analysis']['security_posture']}")
    
    print("\nKey Findings:")
    for finding in analysis['analysis']['key_findings']:
        print(f"- {finding}")
    
    print("\nAttack Surface:")
    for surface in analysis['analysis']['attack_surface']:
        print(f"- {surface}")
    
    print("\nTop Recommendations:")
    for i, rec in enumerate(analysis['recommendations'][:3], 1):
        print(f"{i}. [{rec['priority'].upper()}] {rec['action']}")
        print(f"   {rec['description']}")
    
    print(f"\nOverall Risk Assessment: {analysis['risk_assessment']['risk_level'].upper()}")
    print(f"Risk Score: {analysis['risk_assessment']['risk_score']}/100")


def demonstrate_service_specific_scanning():
    """Demonstrate service-specific scanning capabilities."""
    print("\n=== Service-Specific Scanning Demo ===\n")
    
    target = "127.0.0.1"
    
    # 1. Web Application Scanning
    print("1. Web Application Security Scan")
    print("-" * 30)
    
    # First check if web service is running
    from diagnostics.security_scanner import scan_tcp_port
    
    if scan_tcp_port(target, 80)['state'] == 'open':
        http_vulns = script_scanning.scan_http_vulnerabilities(target, 80, ssl_enabled=False)
        print(f"   Security Headers Missing: {len([h for h, v in http_vulns['security_headers'].items() if not v])}")
        print(f"   Vulnerabilities Found: {len(http_vulns['vulnerabilities'])}")
        for vuln in http_vulns['vulnerabilities'][:3]:
            print(f"   - [{vuln['severity'].upper()}] {vuln['description']}")
    else:
        print("   HTTP service not running on port 80")
    
    # 2. Database Security Scan
    print("\n2. Database Security Scan")
    print("-" * 30)
    
    # Check for common database ports
    db_ports = {
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis'
    }
    
    for port, db_type in db_ports.items():
        if scan_tcp_port(target, port)['state'] == 'open':
            print(f"   {db_type} detected on port {port}")
            db_result = script_scanning.scan_database_security(target, port, db_type.lower())
            print(f"   Configuration Issues: {len(db_result['configuration_issues'])}")
            print(f"   Security Vulnerabilities: {len(db_result['vulnerabilities'])}")
            break
    else:
        print("   No database services detected")


def demonstrate_modular_functions():
    """Demonstrate individual modular functions for Claude Code."""
    print("\n=== Modular Function Demo ===\n")
    print("Examples of individual functions Claude Code can call:\n")
    
    target = "127.0.0.1"
    
    # 1. Direct service banner grabbing
    print("1. Direct Service Banner Grabbing")
    banner_result = service_detection.detect_service_banner(target, 22)
    print(f"   Port 22: {banner_result['service']}")
    if banner_result.get('banner'):
        print(f"   Banner: {banner_result['banner']}")
    
    # 2. TTL-based OS detection
    print("\n2. TTL-based OS Detection")
    ttl_result = os_fingerprinting.detect_os_by_ttl(target)
    print(f"   TTL: {ttl_result.get('ttl', 'N/A')}")
    print(f"   Probable OS: {ttl_result['probable_os']}")
    print(f"   Confidence: {ttl_result['confidence']:.1%}")
    
    # 3. Well-known service scanning
    print("\n3. Well-Known Service Scan")
    services = service_detection.scan_well_known_services(target, timeout=1.0)
    print(f"   Found {len(services)} services:")
    for svc in services[:5]:
        print(f"   - Port {svc['port']}: {svc['service']}")


def main():
    """Main demonstration function."""
    print("=" * 60)
    print("SuperSleuth Network - Network Scanning Demonstration")
    print("=" * 60)
    print("\nThis demo shows how Claude Code can orchestrate network")
    print("scanning modules to perform comprehensive diagnostics.")
    
    # Safety warning
    print("\n⚠️  WARNING: Only scan systems you own or have permission to test!")
    print("This demo uses localhost (127.0.0.1) for safety.")
    
    try:
        # Run demonstrations
        demonstrate_basic_scanning()
        demonstrate_workflow()
        demonstrate_service_specific_scanning()
        demonstrate_modular_functions()
        
        # Only run external scan if explicitly enabled
        if '--external' in sys.argv:
            demonstrate_intelligent_analysis()
        else:
            print("\n(Skip external scan demo - use --external flag to enable)")
            
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()