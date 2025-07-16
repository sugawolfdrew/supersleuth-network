#!/usr/bin/env python3
"""
Integrated Network Scanning Example

This example shows how the new modular scanning functions integrate with
the existing NetworkDiscovery class and can be orchestrated by Claude Code.
"""

import sys
import json
from typing import Dict, List, Any

# Add the src directory to the path
sys.path.insert(0, '../src')

from diagnostics.network_discovery import NetworkDiscovery
from diagnostics.diagnostic_api import NetworkDiagnosticAPI
from diagnostics import service_detection, os_fingerprinting


class IntegratedNetworkScanner:
    """
    Example class showing how Claude Code can integrate existing and new modules.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.api = NetworkDiagnosticAPI(config)
        
    def comprehensive_network_analysis(self, target_subnet: str, 
                                     authorized: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive network analysis combining all modules.
        
        This is an example of how Claude Code might orchestrate multiple
        diagnostic tools based on an IT professional's request.
        """
        results = {
            'subnet': target_subnet,
            'discovery': {},
            'detailed_scans': {},
            'summary': {},
            'recommendations': []
        }
        
        # Step 1: Network Discovery (if authorized)
        if authorized:
            print(f"\n[Step 1] Discovering devices in {target_subnet}...")
            discovery = NetworkDiscovery(
                config=self.config,
                authorized_subnets=[target_subnet]
            )
            
            # Would normally check prerequisites and get authorization
            # For demo, we'll simulate the discovery
            print("  ⚠️  Network discovery requires authorization")
            results['discovery'] = {
                'status': 'requires_authorization',
                'message': 'Network discovery on subnet requires explicit authorization'
            }
        else:
            print(f"\n[Step 1] Skipping subnet discovery (not authorized)")
            results['discovery'] = {'status': 'skipped'}
            
        # Step 2: If we have specific targets, scan them
        # For demo, we'll scan a single target
        target_ip = target_subnet.split('/')[0]  # Use base IP for demo
        
        print(f"\n[Step 2] Performing detailed scan of {target_ip}...")
        
        # Run diagnostic workflow
        workflow = [
            {'type': 'port_scan', 'params': {'ports': '1-1000'}},
            {'type': 'service_detection', 'use_previous': 'open_ports'},
            {'type': 'os_detection', 'use_previous': 'open_ports'},
            {'type': 'vulnerability_scan', 'use_previous': 'services'}
        ]
        
        detailed_results = self.api.run_workflow(target_ip, workflow)
        results['detailed_scans'][target_ip] = detailed_results
        
        # Step 3: Generate comprehensive summary
        print("\n[Step 3] Generating analysis summary...")
        results['summary'] = self._generate_summary(results)
        
        # Step 4: Generate recommendations
        print("\n[Step 4] Generating recommendations...")
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
        
    def quick_security_check(self, target: str) -> Dict[str, Any]:
        """
        Perform a quick security check on a specific target.
        
        Example of a focused diagnostic that Claude Code might run.
        """
        print(f"\n🔍 Quick Security Check: {target}")
        print("-" * 50)
        
        # Quick scan of common vulnerable ports
        vulnerable_ports = [
            21,    # FTP
            23,    # Telnet
            135,   # MS-RPC
            139,   # NetBIOS
            445,   # SMB
            1433,  # MS-SQL
            3389,  # RDP
            5900,  # VNC
        ]
        
        # Scan for vulnerable services
        from diagnostics.security_scanner import scan_tcp_ports_batch
        
        print("Checking for vulnerable services...")
        open_ports = scan_tcp_ports_batch(target, vulnerable_ports, timeout=2.0)
        
        results = {
            'target': target,
            'vulnerable_services': [],
            'risk_level': 'low',
            'findings': []
        }
        
        # Check each open port
        for port_info in open_ports:
            if port_info['state'] == 'open':
                port = port_info['port']
                
                # Identify service
                service_info = service_detection.detect_service_banner(target, port)
                
                # Flag vulnerable services
                if port in [21, 23, 5900]:  # FTP, Telnet, VNC
                    results['vulnerable_services'].append({
                        'port': port,
                        'service': service_info.get('service', 'unknown'),
                        'risk': 'high',
                        'reason': 'Insecure protocol - transmits data in plaintext'
                    })
                    results['risk_level'] = 'high'
                elif port in [135, 139, 445]:  # Windows services
                    results['vulnerable_services'].append({
                        'port': port,
                        'service': service_info.get('service', 'unknown'),
                        'risk': 'medium',
                        'reason': 'Windows service exposed to network'
                    })
                    if results['risk_level'] == 'low':
                        results['risk_level'] = 'medium'
                        
        # Generate findings
        if results['vulnerable_services']:
            results['findings'].append({
                'type': 'vulnerable_services',
                'severity': results['risk_level'],
                'description': f"Found {len(results['vulnerable_services'])} potentially vulnerable services",
                'recommendation': 'Review and secure or disable these services'
            })
            
        return results
        
    def diagnose_connectivity_issue(self, source: str, target: str, 
                                   service: str = None) -> Dict[str, Any]:
        """
        Diagnose connectivity issues between two points.
        
        Example of how Claude Code might troubleshoot connectivity problems.
        """
        print(f"\n🔧 Diagnosing Connectivity: {source} → {target}")
        if service:
            print(f"   Service: {service}")
        print("-" * 50)
        
        results = {
            'source': source,
            'target': target,
            'service': service,
            'connectivity': {},
            'diagnosis': [],
            'solutions': []
        }
        
        # Step 1: Basic connectivity test
        print("\n[1] Testing basic connectivity...")
        # Would use ping/traceroute here
        
        # Step 2: Port-specific test if service specified
        if service:
            service_ports = {
                'ssh': 22,
                'http': 80,
                'https': 443,
                'rdp': 3389,
                'smb': 445,
                'mysql': 3306,
                'postgresql': 5432
            }
            
            port = service_ports.get(service.lower())
            if port:
                print(f"\n[2] Testing {service} service on port {port}...")
                
                from diagnostics.security_scanner import scan_tcp_port
                port_result = scan_tcp_port(target, port)
                
                results['connectivity']['port_status'] = port_result['state']
                
                if port_result['state'] == 'open':
                    # Service is accessible
                    print(f"   ✅ Port {port} is open")
                    
                    # Get service details
                    service_info = service_detection.detect_service_banner(target, port)
                    results['connectivity']['service_info'] = service_info
                    
                    results['diagnosis'].append({
                        'finding': 'service_accessible',
                        'details': f"{service} service is running and accessible"
                    })
                else:
                    # Service not accessible
                    print(f"   ❌ Port {port} is {port_result['state']}")
                    
                    results['diagnosis'].append({
                        'finding': 'port_not_accessible',
                        'details': f"Port {port} is {port_result['state']}"
                    })
                    
                    # Generate possible causes
                    if port_result['state'] == 'closed':
                        results['solutions'].append(
                            f"Start the {service} service on the target server"
                        )
                    elif port_result['state'] == 'filtered':
                        results['solutions'].extend([
                            "Check firewall rules blocking port " + str(port),
                            "Verify network ACLs between source and target",
                            "Check if service is bound to localhost only"
                        ])
                        
        return results
        
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary from scan results."""
        summary = {
            'total_hosts_scanned': 0,
            'total_open_ports': 0,
            'services_detected': [],
            'os_detected': [],
            'vulnerabilities': 0,
            'risk_level': 'low'
        }
        
        # Aggregate results
        for ip, scan_data in results.get('detailed_scans', {}).items():
            if 'summary' in scan_data:
                summary['total_hosts_scanned'] += 1
                summary['total_open_ports'] += scan_data['summary'].get('total_open_ports', 0)
                summary['services_detected'].extend(scan_data['summary'].get('detected_services', []))
                summary['vulnerabilities'] += len(scan_data['summary'].get('vulnerabilities', []))
                
                # Update risk level
                scan_risk = scan_data['summary'].get('risk_level', 'low')
                if scan_risk == 'critical' or summary['risk_level'] == 'critical':
                    summary['risk_level'] = 'critical'
                elif scan_risk == 'high' or summary['risk_level'] == 'high':
                    summary['risk_level'] = 'high'
                elif scan_risk == 'medium' and summary['risk_level'] not in ['high', 'critical']:
                    summary['risk_level'] = 'medium'
                    
        # Deduplicate services
        summary['services_detected'] = list(set(summary['services_detected']))
        
        return summary
        
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        summary = results.get('summary', {})
        
        # Check risk level
        if summary.get('risk_level') in ['critical', 'high']:
            recommendations.append(
                "🚨 URGENT: Address critical vulnerabilities immediately"
            )
            
        # Check for vulnerable services
        vulnerable_services = ['telnet', 'ftp', 'vnc']
        for service in summary.get('services_detected', []):
            if service.lower() in vulnerable_services:
                recommendations.append(
                    f"Replace {service} with a secure alternative (e.g., SSH instead of Telnet)"
                )
                
        # Check for excessive open ports
        if summary.get('total_open_ports', 0) > 20:
            recommendations.append(
                "Review and close unnecessary open ports to reduce attack surface"
            )
            
        # Add general security recommendations
        if not recommendations:
            recommendations.append(
                "Maintain current security posture with regular assessments"
            )
            
        return recommendations


def main():
    """Demonstrate integrated network scanning."""
    print("=" * 60)
    print("SuperSleuth Network - Integrated Scanning Demo")
    print("=" * 60)
    
    scanner = IntegratedNetworkScanner()
    
    # Demo 1: Quick Security Check
    print("\n📋 Demo 1: Quick Security Check")
    security_result = scanner.quick_security_check("127.0.0.1")
    
    print(f"\nRisk Level: {security_result['risk_level'].upper()}")
    if security_result['vulnerable_services']:
        print("\nVulnerable Services Found:")
        for vuln in security_result['vulnerable_services']:
            print(f"  - Port {vuln['port']} ({vuln['service']}): {vuln['reason']}")
    else:
        print("\n✅ No vulnerable services found")
        
    # Demo 2: Connectivity Diagnosis
    print("\n\n📋 Demo 2: Connectivity Diagnosis")
    conn_result = scanner.diagnose_connectivity_issue(
        source="workstation",
        target="127.0.0.1",
        service="ssh"
    )
    
    print("\nDiagnosis:")
    for diag in conn_result['diagnosis']:
        print(f"  - {diag['details']}")
        
    if conn_result['solutions']:
        print("\nSuggested Solutions:")
        for solution in conn_result['solutions']:
            print(f"  - {solution}")
            
    # Demo 3: Comprehensive Analysis (simplified)
    print("\n\n📋 Demo 3: Comprehensive Network Analysis")
    print("(This would normally scan an entire subnet)")
    
    # For demo, just analyze single host
    analysis = scanner.comprehensive_network_analysis("127.0.0.1/32", authorized=False)
    
    print(f"\nSummary:")
    print(f"  Risk Level: {analysis['summary'].get('risk_level', 'unknown').upper()}")
    print(f"  Open Ports: {analysis['summary'].get('total_open_ports', 0)}")
    print(f"  Services: {', '.join(analysis['summary'].get('services_detected', [])) or 'None'}")
    
    if analysis['recommendations']:
        print("\nRecommendations:")
        for rec in analysis['recommendations']:
            print(f"  - {rec}")
            
    print("\n" + "=" * 60)
    print("Integration Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()