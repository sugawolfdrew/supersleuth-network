#!/usr/bin/env python3
"""
Claude Code Scenario: Security Incident Response

This script demonstrates how Claude Code handles natural language requests
for security incidents, showing rapid assessment and response workflows.
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.claude_code_integration import ClaudeCodeIntegration


class SecurityIncidentScenarios:
    """Collection of security incident response scenarios"""
    
    def __init__(self):
        self.claude = ClaudeCodeIntegration()
    
    async def scenario_suspicious_outbound(self):
        """Scenario 1: Suspicious outbound traffic detected"""
        print("="*80)
        print("SCENARIO 1: Suspicious Outbound Traffic")
        print("="*80)
        
        request = """
        URGENT: Security monitoring detected unusual outbound traffic from 
        server 10.1.50.45 to multiple external IPs (185.220.101.0/24 range)
        on ports 6667 and 6697 (IRC). Traffic volume is 500MB+ in last hour.
        This server should only communicate internally!
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("⚠️  SECURITY INCIDENT DETECTED - Engaging rapid response mode")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("IMMEDIATE ACTIONS TAKEN:")
        print("-"*40)
        
        print("\n1. CONTAINMENT (First 60 seconds):")
        print("   - Initiated traffic capture on affected server")
        print("   - Blocked outbound IRC ports at firewall")
        print("   - Isolated server from sensitive segments")
        
        print("\n2. ASSESSMENT Tools Deployed:")
        print("   - SecurityAssessment: Full port scan of 10.1.50.45")
        print("   - AdvancedDiagnostics: Traffic pattern analysis")
        print("   - NetworkMetrics: Historical baseline comparison")
        print("   - DNSDiagnostics: Malicious domain lookups")
        
        print("\n3. INVESTIGATION Progress:")
        print("   - Identified 3 active IRC connections")
        print("   - Detected potential bot behavior (beaconing)")
        print("   - Found suspicious process 'systemd-update'")
        print("   - Discovered data exfiltration patterns")
        
        print("\n" + "-"*40)
        print("INCIDENT REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_port_scan_detected(self):
        """Scenario 2: External port scan detected"""
        print("\n\n" + "="*80)
        print("SCENARIO 2: External Port Scan Attack")
        print("="*80)
        
        request = """
        IDS alerts showing port scan from 203.0.113.50 targeting our 
        public web servers (DMZ subnet 172.16.1.0/24). Over 10,000 
        connection attempts in past 10 minutes. Scanning sequential 
        ports 1-65535. Need immediate assessment and response.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DEFENSIVE ACTIONS WORKFLOW:")
        print("-"*40)
        
        print("\n1. Real-time Monitoring:")
        print("   - PortScanner: Identify exposed services")
        print("   - NetworkMetrics: Monitor connection rates")
        print("   - SecurityAssessment: Vulnerability quick scan")
        
        print("\n2. Immediate Mitigations:")
        print("   - Rate limiting applied to source IP")
        print("   - Non-essential ports closed")
        print("   - IPS signatures updated")
        print("   - Backup firewall rules activated")
        
        print("\n3. Intelligence Gathering:")
        print("   - Source IP reputation check")
        print("   - GeoIP location: Eastern Europe")
        print("   - Similar attacks from IP range")
        print("   - Likely automated scanner bot")
        
        print("\n" + "-"*40)
        print("SECURITY ASSESSMENT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_data_exfiltration(self):
        """Scenario 3: Potential data exfiltration"""
        print("\n\n" + "="*80)
        print("SCENARIO 3: Data Exfiltration Suspected")
        print("="*80)
        
        request = """
        Database server 10.2.10.20 showing unusual activity. Massive 
        outbound data transfer (50GB+) to cloud storage service at 
        unusual hours (3 AM). Server contains customer PII data.
        No scheduled backups run at this time. Compliance team alerted.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("🚨 DATA BREACH POTENTIAL - Initiating incident response")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("INCIDENT RESPONSE TIMELINE:")
        print("-"*40)
        
        print("\nT+0 min - Detection & Containment:")
        print("  - Blocked cloud storage destination IPs")
        print("  - Enabled full packet capture")
        print("  - Notified incident response team")
        
        print("\nT+5 min - Rapid Assessment:")
        print("  - AdvancedDiagnostics: Analyzing transfer patterns")
        print("  - SecurityAssessment: Checking access logs")
        print("  - HTTPDiagnostics: Identifying cloud endpoints")
        
        print("\nT+10 min - Forensic Collection:")
        print("  - Captured memory dump from server")
        print("  - Preserved network flows")
        print("  - Backed up system logs")
        print("  - Documented timeline")
        
        print("\n" + "-"*40)
        print("INCIDENT FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_ransomware_indicators(self):
        """Scenario 4: Ransomware indicators detected"""
        print("\n\n" + "="*80)
        print("SCENARIO 4: Ransomware Indicators")
        print("="*80)
        
        request = """
        Multiple file servers showing high CPU and disk activity.
        Users reporting files becoming inaccessible with .locked extension.
        Unusual network traffic to TOR exit nodes detected.
        Spreading rapidly through file shares. HELP!!!
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("🔴 RANSOMWARE DETECTED - EMERGENCY RESPONSE ACTIVATED")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("EMERGENCY CONTAINMENT PROTOCOL:")
        print("-"*40)
        
        print("\n1. IMMEDIATE ISOLATION (0-2 minutes):")
        print("   ✓ Disconnected affected servers from network")
        print("   ✓ Disabled file sharing protocols")
        print("   ✓ Blocked TOR exit nodes at firewall")
        print("   ✓ Initiated network segmentation")
        
        print("\n2. RAPID ASSESSMENT (2-5 minutes):")
        print("   - TopologyInterference: Mapping infection spread")
        print("   - SecurityAssessment: Identifying patient zero")
        print("   - NetworkMetrics: Tracking lateral movement")
        print("   - PortScanner: Finding C2 communications")
        
        print("\n3. DAMAGE CONTROL (5-10 minutes):")
        print("   ✓ Powered off uninfected critical systems")
        print("   ✓ Activated offline backups")
        print("   ✓ Deployed ransomware kill switches")
        print("   ✓ Initiated disaster recovery plan")
        
        print("\n" + "-"*40)
        print("RANSOMWARE ANALYSIS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_insider_threat(self):
        """Scenario 5: Potential insider threat"""
        print("\n\n" + "="*80)
        print("SCENARIO 5: Insider Threat Detection")
        print("="*80)
        
        request = """
        Unusual activity from user account 'jsmith' - accessing systems 
        never used before, downloading large amounts of data from 
        different departments. Login times are outside normal hours.
        User gave notice last week. Accessing from 10.1.15.230.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("👤 INSIDER THREAT ASSESSMENT - Discrete monitoring activated")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("INSIDER THREAT INVESTIGATION:")
        print("-"*40)
        
        print("\n1. Behavioral Analysis:")
        print("   - Normal access pattern: 9 AM - 5 PM, Finance systems only")
        print("   - Current pattern: 11 PM - 3 AM, accessing HR, Legal, R&D")
        print("   - Data volume: 10x normal daily average")
        
        print("\n2. Discrete Monitoring Tools:")
        print("   - NetworkMetrics: Tracking all connections from 10.1.15.230")
        print("   - AdvancedDiagnostics: Data transfer analysis")
        print("   - SecurityAssessment: Privilege escalation check")
        print("   - HTTPDiagnostics: Cloud storage uploads")
        
        print("\n3. Evidence Collection:")
        print("   - All network activity logged")
        print("   - File access audit trail preserved")
        print("   - Screenshot capabilities enabled")
        print("   - Legal team notified")
        
        print("\n" + "-"*40)
        print("THREAT ASSESSMENT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_zero_day_exploit(self):
        """Scenario 6: Potential zero-day exploitation"""
        print("\n\n" + "="*80)
        print("SCENARIO 6: Zero-Day Exploit Suspected")
        print("="*80)
        
        request = """
        Web application servers crashing with unknown error patterns.
        IDS not detecting known attack signatures but seeing malformed
        HTTP requests. Memory corruption detected. Several servers 
        compromised within minutes. Exploit targets our custom API.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("⚡ ZERO-DAY ATTACK - Advanced threat response engaged")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("ADVANCED THREAT RESPONSE:")
        print("-"*40)
        
        print("\n1. Exploit Analysis:")
        print("   - HTTPDiagnostics: Capturing malformed requests")
        print("   - AdvancedDiagnostics: Memory dump analysis")
        print("   - SecurityAssessment: Vulnerability fingerprinting")
        
        print("\n2. Adaptive Defense:")
        print("   - Created custom WAF rules based on attack pattern")
        print("   - Deployed honeypot to capture exploit")
        print("   - Enabled enhanced logging")
        print("   - Isolated affected API endpoints")
        
        print("\n3. Threat Intelligence:")
        print("   - Attack pattern: Buffer overflow in API parser")
        print("   - Payload: Reverse shell installation")
        print("   - Attribution: Advanced persistent threat")
        print("   - Similar attacks: None found (confirming zero-day)")
        
        print("\n" + "-"*40)
        print("ZERO-DAY ASSESSMENT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    def demonstrate_security_priorities(self):
        """Show how Claude prioritizes different security incidents"""
        print("\n\n" + "="*80)
        print("SECURITY INCIDENT PRIORITIZATION")
        print("="*80)
        
        incidents = [
            ("Critical", "Ransomware actively encrypting file servers"),
            ("Critical", "Data exfiltration of customer database in progress"),
            ("High", "Suspicious outbound IRC traffic from production server"),
            ("High", "Zero-day exploit targeting public web application"),
            ("Medium", "Port scan detected from external source"),
            ("Medium", "Insider threat suspected - unusual access patterns"),
            ("Low", "Failed login attempts on VPN gateway"),
            ("Low", "Outdated SSL certificate on internal server")
        ]
        
        print("\nClaude Code prioritizes security incidents based on:")
        print("- Active vs potential threat")
        print("- Data sensitivity and compliance impact")
        print("- Spread potential and blast radius")
        print("- Business impact and criticality\n")
        
        for priority, incident in incidents:
            context = self.claude.analyze_request(incident)
            print(f"[{priority}] {incident}")
            print(f"        Response time: ", end="")
            
            if priority == "Critical":
                print("IMMEDIATE - Automated containment initiated")
            elif priority == "High":
                print("< 5 minutes - Rapid assessment required")
            elif priority == "Medium":
                print("< 30 minutes - Scheduled investigation")
            else:
                print("< 24 hours - Routine security hygiene")
            print()


async def incident_response_simulator():
    """Interactive incident response simulator"""
    claude = ClaudeCodeIntegration()
    
    print("\n" + "="*80)
    print("SECURITY INCIDENT RESPONSE SIMULATOR")
    print("="*80)
    
    print("\nSimulate a security incident to see Claude Code's response.")
    print("\nChoose an incident type:")
    print("1. Malware infection")
    print("2. Data breach")
    print("3. DDoS attack")
    print("4. Unauthorized access")
    print("5. Custom incident")
    
    choice = input("\nSelect (1-5): ").strip()
    
    templates = {
        '1': "Detected malware infection on workstation 10.1.100.50. "
             "Unusual processes running, attempting to spread via network shares. "
             "Antivirus quarantine failed.",
        
        '2': "Database server 10.2.5.10 transferring large amounts of data "
             "to unknown external IP 198.51.100.50. Contains customer credit card data. "
             "Transfer ongoing for past hour.",
        
        '3': "Website experiencing massive traffic spike - 1000x normal volume. "
             "All from different IPs. Site becoming unresponsive. "
             "Appears to be distributed attack.",
        
        '4': "Admin account 'root' logged in from unfamiliar IP 203.0.113.99. "
             "Account is modifying firewall rules and creating new users. "
             "No authorized admin activity scheduled.",
        
        '5': ""
    }
    
    if choice == '5':
        request = input("\nDescribe your security incident:\n> ")
    else:
        request = templates.get(choice, templates['1'])
        print(f"\nIncident: {request}")
    
    print("\n" + "-"*40)
    print("INITIATING INCIDENT RESPONSE...")
    print("-"*40)
    
    # Simulate real-time response
    print("\n⏱️  T+0:00 - Incident detected, Claude Code engaged")
    await asyncio.sleep(1)
    
    print("⏱️  T+0:05 - Analyzing threat indicators...")
    await asyncio.sleep(1)
    
    print("⏱️  T+0:10 - Deploying containment measures...")
    await asyncio.sleep(1)
    
    print("⏱️  T+0:15 - Initiating forensic collection...")
    await asyncio.sleep(1)
    
    print("⏱️  T+0:30 - Generating incident report...\n")
    
    results = await claude.diagnose(request)
    
    print("\n" + "="*40)
    print("INCIDENT RESPONSE REPORT:")
    print("="*40)
    print(results['report'])
    
    print("\n" + "-"*40)
    print("POST-INCIDENT ACTIONS:")
    print("-"*40)
    print("1. Review and approve containment measures")
    print("2. Initiate communications plan")
    print("3. Preserve evidence for investigation")
    print("4. Document lessons learned")
    print("5. Update security controls based on findings")


async def main():
    """Run all security incident scenarios"""
    scenarios = SecurityIncidentScenarios()
    
    # Run each scenario
    await scenarios.scenario_suspicious_outbound()
    await scenarios.scenario_port_scan_detected()
    await scenarios.scenario_data_exfiltration()
    await scenarios.scenario_ransomware_indicators()
    await scenarios.scenario_insider_threat()
    await scenarios.scenario_zero_day_exploit()
    
    # Demonstrate prioritization
    scenarios.demonstrate_security_priorities()
    
    # Offer incident simulator
    print("\n\nWould you like to try the incident response simulator? (y/n): ", end="")
    if input().lower() == 'y':
        await incident_response_simulator()
    
    print("\n✓ Security incident response scenarios completed!")
    print("\n⚠️  Remember: These are simulated scenarios for demonstration.")
    print("In real incidents, always follow your organization's incident response plan.")


if __name__ == "__main__":
    asyncio.run(main())