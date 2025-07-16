#!/usr/bin/env python3
"""
Claude Code Scenario: Diagnosing Connectivity Issues

This script demonstrates how Claude Code handles natural language requests
for connectivity problems, showing various diagnostic approaches.
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.claude_code_integration import ClaudeCodeIntegration


class ConnectivityScenarios:
    """Collection of connectivity diagnostic scenarios"""
    
    def __init__(self):
        self.claude = ClaudeCodeIntegration()
    
    async def scenario_cannot_reach_server(self):
        """Scenario 1: Cannot reach internal server"""
        print("="*80)
        print("SCENARIO 1: Cannot Reach Internal Server")
        print("="*80)
        
        request = """
        Cannot connect to database server at 10.1.5.50 port 3306 from 
        application servers in DMZ (10.2.0.0/24). Connection times out.
        Was working fine until this morning. Other internal services 
        are accessible from DMZ.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. PortScanner - Testing port 3306 accessibility")
        print("2. RoutingDiagnostics - Tracing path DMZ → Database")
        print("3. AdvancedDiagnostics - Firewall rule analysis")
        print("4. NetworkHealthCheck - Checking intermediate devices")
        
        print("\nDiagnostic Steps:")
        print("- Test from DMZ host: ping 10.1.5.50")
        print("- Port scan: 10.1.5.50:3306 from 10.2.0.10")
        print("- Traceroute to identify blocking point")
        print("- Compare with working service routes")
        print("- Check recent firewall changes")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_intermittent_connectivity(self):
        """Scenario 2: Intermittent connectivity issues"""
        print("\n\n" + "="*80)
        print("SCENARIO 2: Intermittent Connectivity")
        print("="*80)
        
        request = """
        Web application at https://app.company.com randomly becomes 
        unreachable throughout the day. Sometimes works fine, then 
        suddenly connection refused or timeout. Affects all users.
        Pattern seems random - not tied to specific times. Very frustrating!
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. HTTPDiagnostics - Continuous monitoring of app.company.com")
        print("2. DNSDiagnostics - DNS resolution consistency check")
        print("3. PortScanner - Monitoring port availability over time")
        print("4. PerformanceAnalyzer - Identifying failure patterns")
        
        print("\nMonitoring Strategy:")
        print("- HTTP health checks every 30 seconds for 1 hour")
        print("- Capture exact failure timestamps")
        print("- DNS resolution from multiple servers")
        print("- Correlate with load balancer logs")
        print("- Check for flapping network interfaces")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_site_to_site_vpn(self):
        """Scenario 3: Site-to-site VPN connectivity"""
        print("\n\n" + "="*80)
        print("SCENARIO 3: Site-to-Site VPN Issues")
        print("="*80)
        
        request = """
        London office (192.168.10.0/24) cannot access any resources in 
        Tokyo office (192.168.20.0/24). Site-to-site VPN shows as connected
        on both endpoints. Can ping VPN gateway IPs but nothing beyond.
        This is blocking critical file transfers between offices.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. RoutingDiagnostics - Test routing between sites")
        print("2. AdvancedDiagnostics - VPN tunnel analysis")
        print("3. NetworkMetrics - Tunnel traffic statistics")
        print("4. SecurityAssessment - IPSec policy verification")
        
        print("\nVPN Diagnostic Approach:")
        print("- Verify Phase 1 and Phase 2 SA establishment")
        print("- Check routing tables on both endpoints")
        print("- Test with different packet sizes (fragmentation)")
        print("- Verify NAT exemption rules")
        print("- Compare working vs non-working traffic")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_cloud_service_access(self):
        """Scenario 4: Cloud service connectivity issues"""
        print("\n\n" + "="*80)
        print("SCENARIO 4: Cloud Service Access Problems")
        print("="*80)
        
        request = """
        Cannot access AWS S3 buckets from production servers. Getting
        'Could not connect to endpoint' errors. Azure and GCP services
        work fine. Only affects production subnet 10.50.0.0/22, dev 
        environment has no issues. Need urgent fix for deployment pipeline.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. DNSDiagnostics - Resolve S3 endpoints")
        print("2. HTTPDiagnostics - Test S3 API endpoints")
        print("3. RoutingDiagnostics - Trace to AWS regions")
        print("4. SecurityAssessment - Check outbound rules")
        
        print("\nCloud Connectivity Analysis:")
        print("- Resolve: s3.amazonaws.com from prod vs dev")
        print("- Test HTTPS connectivity to S3 endpoints")
        print("- Compare routes: AWS vs Azure vs GCP")
        print("- Check proxy/firewall rules for AWS")
        print("- Verify IAM role connectivity")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_selective_connectivity(self):
        """Scenario 5: Selective connectivity failure"""
        print("\n\n" + "="*80)
        print("SCENARIO 5: Selective Connectivity Failure")
        print("="*80)
        
        request = """
        Strange issue - users in finance department can access internet
        and most internal resources, but cannot reach HR system (10.3.1.100),
        payroll system (10.3.1.101), or time tracking (10.3.1.102).
        All three systems are in the same subnet and work for other departments.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. TopologyInterference - Map finance network path")
        print("2. SecurityAssessment - VLAN and ACL analysis")
        print("3. RoutingDiagnostics - Compare working vs blocked paths")
        print("4. PortScanner - Test all ports on affected systems")
        
        print("\nSelective Blocking Analysis:")
        print("- Map Finance VLAN/subnet configuration")
        print("- Check for subnet-based ACLs")
        print("- Test from finance user IP vs others")
        print("- Look for common factors in blocked systems")
        print("- Verify no duplicate IP addresses")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_dns_related_connectivity(self):
        """Scenario 6: DNS-related connectivity issues"""
        print("\n\n" + "="*80)
        print("SCENARIO 6: DNS-Related Connectivity")
        print("="*80)
        
        request = """
        Users report they cannot access internal websites by name but 
        can access them using IP addresses. For example, http://intranet.local
        fails but http://10.1.2.50 works. External websites work fine.
        Started after DNS server maintenance window last night.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. DNSDiagnostics - Comprehensive DNS testing")
        print("2. NetworkHealthCheck - DNS server availability")
        print("3. DHCPDiagnostics - Check DNS settings distribution")
        print("4. RoutingDiagnostics - Verify DNS server connectivity")
        
        print("\nDNS Connectivity Diagnosis:")
        print("- Query internal vs external domains")
        print("- Test all configured DNS servers")
        print("- Check forward and reverse lookups")
        print("- Verify DNS zone configuration")
        print("- Compare DHCP DNS options")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    def demonstrate_connectivity_patterns(self):
        """Show different connectivity issue patterns"""
        print("\n\n" + "="*80)
        print("CONNECTIVITY ISSUE PATTERNS")
        print("="*80)
        
        patterns = {
            "Total Failure": "Cannot reach server 10.1.1.1 at all",
            "Port Specific": "Can ping 10.1.1.1 but cannot connect to port 80",
            "Directional": "Can connect from A to B but not B to A",
            "Time-based": "Connection drops every day at 3 PM",
            "Protocol-specific": "SSH works but HTTPS fails to same server",
            "Subnet-based": "Entire 10.2.0.0/24 subnet unreachable",
            "Service-specific": "All Exchange servers unreachable",
            "Geographic": "All branch offices lost connectivity to HQ"
        }
        
        print("\nCommon connectivity patterns and Claude's approach:\n")
        
        for pattern, example in patterns.items():
            context = self.claude.analyze_request(example)
            print(f"{pattern}:")
            print(f"  Example: \"{example}\"")
            print(f"  Claude identifies: {context.intent.value}")
            print(f"  Key focus: {context.symptoms}")
            print()


async def troubleshooting_wizard():
    """Interactive troubleshooting wizard for connectivity issues"""
    claude = ClaudeCodeIntegration()
    
    print("\n" + "="*80)
    print("CONNECTIVITY TROUBLESHOOTING WIZARD")
    print("="*80)
    
    print("\nAnswer these questions to help diagnose your connectivity issue:\n")
    
    # Gather information
    print("1. What are you trying to connect to?")
    target = input("   (hostname, IP, or service): ").strip()
    
    print("\n2. What exactly happens when you try to connect?")
    print("   a) Connection timeout")
    print("   b) Connection refused") 
    print("   c) Host unreachable")
    print("   d) Works sometimes")
    print("   e) Other")
    symptom = input("   Choose (a-e): ").strip().lower()
    
    print("\n3. When did this start?")
    timeline = input("   (e.g., 'this morning', '2 hours ago'): ").strip()
    
    print("\n4. Who is affected?")
    print("   a) Just me")
    print("   b) My department")
    print("   c) Entire office")
    print("   d) Multiple locations")
    scope = input("   Choose (a-d): ").strip().lower()
    
    print("\n5. Any recent changes you're aware of?")
    changes = input("   (or 'none'): ").strip()
    
    # Build natural language request
    symptom_map = {
        'a': "connection times out",
        'b': "connection is refused",
        'c': "host is unreachable",
        'd': "connection works intermittently",
        'e': "connection fails"
    }
    
    scope_map = {
        'a': "affecting just my computer",
        'b': "affecting my entire department",
        'c': "affecting the whole office",
        'd': "affecting multiple locations"
    }
    
    request = f"""
    Cannot connect to {target}. The {symptom_map.get(symptom, 'connection fails')}.
    This started {timeline}, {scope_map.get(scope, 'affecting some users')}.
    {'Recent changes: ' + changes if changes.lower() != 'none' else 'No recent changes reported.'}
    Need help diagnosing and fixing this connectivity issue.
    """
    
    print("\n" + "-"*40)
    print("Generated diagnostic request:")
    print(request.strip())
    print("-"*40)
    
    print("\nRunning connectivity diagnostics...")
    results = await claude.diagnose(request)
    
    print("\n" + "="*40)
    print("DIAGNOSTIC RESULTS:")
    print("="*40)
    print(results['report'])


async def main():
    """Run all connectivity scenarios"""
    scenarios = ConnectivityScenarios()
    
    # Run each scenario
    await scenarios.scenario_cannot_reach_server()
    await scenarios.scenario_intermittent_connectivity()
    await scenarios.scenario_site_to_site_vpn()
    await scenarios.scenario_cloud_service_access()
    await scenarios.scenario_selective_connectivity()
    await scenarios.scenario_dns_related_connectivity()
    
    # Demonstrate patterns
    scenarios.demonstrate_connectivity_patterns()
    
    # Offer troubleshooting wizard
    print("\n\nWould you like to try the troubleshooting wizard? (y/n): ", end="")
    if input().lower() == 'y':
        await troubleshooting_wizard()
    
    print("\n✓ Connectivity diagnostic scenarios completed!")


if __name__ == "__main__":
    asyncio.run(main())