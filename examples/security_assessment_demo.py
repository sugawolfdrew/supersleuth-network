#!/usr/bin/env python3
"""
Security Assessment Demo - Claude Code Orchestration

This script demonstrates how Claude Code can orchestrate the security
assessment modules to perform customized vulnerability assessments.
"""

import sys
import os
import json
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics import security_scanner
from src.diagnostics import cve_database
from src.diagnostics import vulnerability_reporter
from src.diagnostics.security_assessment import SecurityAssessment


def demonstrate_modular_security_functions():
    """Show how Claude Code can use individual security functions."""
    
    print("=" * 80)
    print("SUPERSLEUTH SECURITY ASSESSMENT - Claude Code Orchestration Demo")
    print("=" * 80)
    print("\nThis demonstrates how Claude Code can orchestrate security modules")
    print("based on natural language requests from IT professionals.\n")
    
    # Example 1: Quick port scan
    print("1. IT Professional: 'Check if web server 192.168.1.100 has any risky ports open'")
    print("   Claude Code orchestrates:")
    print("   - Port scanning for common vulnerable services")
    print("   - Service detection on open ports")
    print("   - Vulnerability assessment\n")
    
    target = "127.0.0.1"  # Using localhost for demo
    
    # Scan common ports
    print(f"   Scanning common ports on {target}...")
    scan_results = security_scanner.scan_common_ports(target, 'all', timeout=0.5)
    
    open_ports = [r for r in scan_results if r['state'] == 'open']
    print(f"   Found {len(open_ports)} open ports")
    
    if open_ports:
        # Check for vulnerable services
        vulnerabilities = security_scanner.check_weak_services(scan_results)
        
        if vulnerabilities:
            print(f"   ⚠️  Found {len(vulnerabilities)} potential vulnerabilities:")
            for vuln in vulnerabilities[:3]:
                print(f"      - {vuln['service']} on port {vuln['port']}: {vuln['issue']}")
        else:
            print("   ✓ No weak services detected on open ports")
    
    print("\n" + "-" * 60 + "\n")
    
    # Example 2: CVE lookup
    print("2. IT Professional: 'Is Apache 2.4.49 vulnerable?'")
    print("   Claude Code orchestrates:")
    print("   - CVE database search for Apache vulnerabilities")
    print("   - Risk assessment based on CVSS scores\n")
    
    print("   Searching CVE database...")
    cves = cve_database.search_cves_by_service('Apache', '2.4.49')
    
    if cves:
        print(f"   Found {len(cves)} CVEs for Apache 2.4.49:")
        for cve in cves[:3]:
            risk = cve_database.calculate_risk_score(cve)
            print(f"      - {cve['cve_id']}: {cve.get('severity', 'UNKNOWN')} "
                  f"(Risk Score: {risk['risk_score']}/10)")
            print(f"        {cve.get('description', 'No description')[:80]}...")
    else:
        print("   No known CVEs found (checking cached data only)")
    
    print("\n" + "-" * 60 + "\n")
    
    # Example 3: Security report generation
    print("3. IT Professional: 'Generate a security report for the scan results'")
    print("   Claude Code orchestrates:")
    print("   - Vulnerability data formatting")
    print("   - Executive summary generation")
    print("   - Remediation plan creation\n")
    
    # Create sample vulnerabilities for reporting
    sample_vulns = []
    if vulnerabilities:
        sample_vulns.extend(vulnerabilities)
    
    # Add a sample CVE finding
    sample_vulns.append({
        'type': 'cve_vulnerability',
        'host': target,
        'port': 80,
        'service': 'Apache',
        'severity': 'HIGH',
        'cve_id': 'CVE-2021-41773',
        'issue': 'Path traversal and RCE vulnerability',
        'recommendation': 'Update Apache to version 2.4.51 or later'
    })
    
    if sample_vulns:
        # Generate executive summary
        metadata = {
            'target': target,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'scan_type': 'Security Assessment Demo'
        }
        
        summary = vulnerability_reporter.generate_executive_summary(sample_vulns, metadata)
        print("   Generated Executive Summary:")
        print("   " + "-" * 40)
        for line in summary.split('\n')[:15]:  # First 15 lines
            print(f"   {line}")
        print("   ...")
    
    print("\n" + "-" * 60 + "\n")


def demonstrate_full_security_scan():
    """Show a complete security scan orchestration."""
    
    print("4. IT Professional: 'Run a complete security assessment'")
    print("   Claude Code orchestrates:")
    print("   - Comprehensive port scanning")
    print("   - Service detection and fingerprinting")
    print("   - CVE correlation")
    print("   - SSL/TLS validation")
    print("   - Report generation\n")
    
    target = "127.0.0.1"
    
    print(f"   Running comprehensive security scan on {target}...")
    
    # Perform full security scan
    scan_results = security_scanner.perform_security_scan(target, 'basic')
    
    print("\n   Scan Results Summary:")
    print(f"   - Status: {scan_results.get('status', 'unknown')}")
    print(f"   - Open Ports: {len([p for p in scan_results.get('port_scan', []) if p['state'] == 'open'])}")
    print(f"   - Services Detected: {len(scan_results.get('services', []))}")
    print(f"   - Vulnerabilities Found: {len(scan_results.get('vulnerabilities', []))}")
    print(f"   - SSL Issues: {len(scan_results.get('ssl_checks', []))}")
    
    # Generate recommendations
    if scan_results.get('recommendations'):
        print("\n   Security Recommendations:")
        for i, rec in enumerate(scan_results['recommendations'][:5], 1):
            print(f"   {i}. {rec}")


def demonstrate_claude_code_patterns():
    """Show how Claude Code would interpret different requests."""
    
    print("\n" + "=" * 80)
    print("CLAUDE CODE PATTERN EXAMPLES")
    print("=" * 80)
    
    patterns = [
        {
            'request': "Check if server X is vulnerable to known exploits",
            'modules': ['scan_tcp_ports_batch', 'detect_services_batch', 'search_cves_by_service'],
            'workflow': "Port scan → Service detection → CVE lookup → Risk assessment"
        },
        {
            'request': "Scan network for weak encryption",
            'modules': ['scan_common_ports', 'check_ssl_certificate', 'check_weak_services'],
            'workflow': "Find SSL/TLS ports → Check certificates → Identify weak protocols"
        },
        {
            'request': "Generate compliance report for PCI DSS",
            'modules': ['perform_security_scan', 'generate_detailed_findings', 'export_as_html'],
            'workflow': "Full scan → Filter PCI-relevant findings → Format for compliance"
        },
        {
            'request': "Find all exposed databases on the network",
            'modules': ['scan_tcp_range', 'detect_service_banner', 'check_weak_services'],
            'workflow': "Scan DB ports (3306,5432,1433,etc) → Verify services → Check auth"
        }
    ]
    
    for pattern in patterns:
        print(f"\nRequest: '{pattern['request']}'")
        print(f"Modules: {', '.join(pattern['modules'])}")
        print(f"Workflow: {pattern['workflow']}")


def main():
    """Run all demonstrations."""
    
    # Show modular function usage
    demonstrate_modular_security_functions()
    
    # Show full scan orchestration
    demonstrate_full_security_scan()
    
    # Show Claude Code patterns
    demonstrate_claude_code_patterns()
    
    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE")
    print("=" * 80)
    print("\nKey Takeaways:")
    print("1. Security functions are modular and can be called independently")
    print("2. Claude Code can combine functions based on the specific request")
    print("3. Results can be formatted for different audiences (technical vs executive)")
    print("4. The system integrates real scanning with CVE databases")
    print("5. All functions are designed to be safe and non-intrusive")


if __name__ == "__main__":
    main()