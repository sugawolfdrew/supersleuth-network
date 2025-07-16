#!/usr/bin/env python3
"""
Claude Code Security Workflow Examples

This file demonstrates how Claude Code can create custom security
workflows by orchestrating the modular security functions based on
natural language requests from IT professionals.
"""

import sys
import os
import asyncio
from typing import Dict, List, Any

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics import security_scanner
from src.diagnostics import cve_database
from src.diagnostics import vulnerability_reporter


class SecurityWorkflowOrchestrator:
    """
    Demonstrates how Claude Code orchestrates security modules
    based on different IT professional requests.
    """
    
    def __init__(self):
        self.workflows = {
            'quick_check': self.quick_security_check,
            'web_app_assessment': self.web_application_assessment,
            'database_audit': self.database_security_audit,
            'compliance_scan': self.compliance_focused_scan,
            'incident_response': self.incident_response_scan
        }
    
    async def interpret_request(self, request: str) -> str:
        """
        Simulate how Claude Code would interpret a natural language request
        and select the appropriate workflow.
        """
        request_lower = request.lower()
        
        # Pattern matching for workflow selection
        if any(word in request_lower for word in ['quick', 'fast', 'basic']):
            workflow_key = 'quick_check'
        elif any(word in request_lower for word in ['web', 'website', 'http', 'api']):
            workflow_key = 'web_app_assessment'
        elif any(word in request_lower for word in ['database', 'sql', 'mongo', 'db']):
            workflow_key = 'database_audit'
        elif any(word in request_lower for word in ['compliance', 'pci', 'hipaa', 'audit']):
            workflow_key = 'compliance_scan'
        elif any(word in request_lower for word in ['incident', 'breach', 'attack', 'compromise']):
            workflow_key = 'incident_response'
        else:
            workflow_key = 'quick_check'
        
        print(f"\n🤖 Claude Code: I understand you need a {workflow_key.replace('_', ' ')}.")
        print(f"   I'll orchestrate the appropriate security modules for this task.\n")
        
        # Execute the selected workflow
        workflow_func = self.workflows.get(workflow_key, self.quick_security_check)
        return await workflow_func(request)
    
    async def quick_security_check(self, request: str) -> str:
        """
        Workflow 1: Quick Security Check
        For requests like: "Give me a quick security overview of server X"
        """
        print("🔍 QUICK SECURITY CHECK WORKFLOW")
        print("=" * 50)
        print("Modules orchestrated:")
        print("1. scan_common_ports() - Check for risky services")
        print("2. check_weak_services() - Identify vulnerabilities")
        print("3. generate_executive_summary() - Create brief report")
        
        # Simulate the workflow
        target = "192.168.1.100"  # Extract from request in real implementation
        
        print(f"\n⚡ Scanning {target} for common vulnerabilities...")
        
        # Step 1: Quick port scan
        print("   → Running port scan on common services...")
        # In real implementation:
        # ports = security_scanner.scan_common_ports(target, 'all', timeout=1.0)
        
        # Step 2: Check for weak services
        print("   → Analyzing services for security risks...")
        # vulnerabilities = security_scanner.check_weak_services(ports)
        
        # Step 3: Generate summary
        print("   → Generating executive summary...")
        # summary = vulnerability_reporter.generate_executive_summary(vulnerabilities)
        
        return """
✅ Quick Security Check Complete

FINDINGS:
- 3 potentially vulnerable services detected
- 1 critical issue: Telnet (port 23) is enabled
- 2 medium issues: Unencrypted FTP and exposed database

IMMEDIATE ACTIONS:
1. Disable Telnet service immediately
2. Replace FTP with SFTP
3. Restrict database access to application servers only

Risk Score: 7.2/10 (HIGH)
"""
    
    async def web_application_assessment(self, request: str) -> str:
        """
        Workflow 2: Web Application Security Assessment
        For requests like: "Check our web app for vulnerabilities"
        """
        print("🌐 WEB APPLICATION ASSESSMENT WORKFLOW")
        print("=" * 50)
        print("Modules orchestrated:")
        print("1. scan_tcp_ports_batch([80, 443, 8080, 8443])")
        print("2. check_ssl_certificate() for each HTTPS port")
        print("3. detect_service_banner() for version info")
        print("4. search_cves_by_service() for known vulnerabilities")
        print("5. generate_detailed_findings(group_by='service')")
        
        print("\n🔒 Assessing web application security...")
        
        # Workflow steps
        print("   → Scanning web service ports...")
        print("   → Validating SSL/TLS certificates...")
        print("   → Detecting web server versions...")
        print("   → Checking for known CVEs...")
        print("   → Generating detailed report...")
        
        return """
✅ Web Application Assessment Complete

SSL/TLS FINDINGS:
- Certificate expires in 15 days (WARNING)
- TLS 1.0/1.1 still enabled (should disable)
- HSTS not configured

SERVICE DETECTION:
- Apache 2.4.49 detected (CRITICAL: CVE-2021-41773)
- PHP 7.2.5 (outdated, multiple vulnerabilities)

RECOMMENDATIONS:
1. URGENT: Update Apache immediately (RCE vulnerability)
2. Renew SSL certificate
3. Disable TLS 1.0/1.1, enable TLS 1.3
4. Implement security headers (HSTS, CSP, etc.)
5. Update PHP to latest 8.x version
"""
    
    async def database_security_audit(self, request: str) -> str:
        """
        Workflow 3: Database Security Audit
        For requests like: "Audit our database servers for security"
        """
        print("🗄️ DATABASE SECURITY AUDIT WORKFLOW")
        print("=" * 50)
        print("Modules orchestrated:")
        print("1. scan_tcp_ports_batch([3306, 5432, 1433, 27017, 6379])")
        print("2. detect_service_banner() for each open DB port")
        print("3. check_weak_services() for authentication issues")
        print("4. perform_security_scan(scan_type='database')")
        print("5. generate_remediation_plan()")
        
        print("\n🔍 Auditing database security...")
        
        # Workflow steps
        print("   → Scanning for database services...")
        print("   → Checking authentication mechanisms...")
        print("   → Testing for default credentials...")
        print("   → Analyzing network exposure...")
        print("   → Creating remediation plan...")
        
        return """
✅ Database Security Audit Complete

CRITICAL FINDINGS:
- MongoDB (27017) accessible without authentication
- Redis (6379) exposed to network (should be localhost only)
- MySQL (3306) using weak authentication plugin

NETWORK EXPOSURE:
- 3 databases accessible from any IP (HIGH RISK)
- No network segmentation detected
- Database backup ports also exposed

REMEDIATION PLAN:
Phase 1 (Immediate):
1. Enable MongoDB authentication
2. Bind Redis to localhost only
3. Implement firewall rules

Phase 2 (This Week):
1. Implement network segmentation
2. Update MySQL authentication
3. Rotate all database credentials

Phase 3 (This Month):
1. Implement database activity monitoring
2. Set up automated security scanning
3. Document access procedures
"""
    
    async def compliance_focused_scan(self, request: str) -> str:
        """
        Workflow 4: Compliance-Focused Security Scan
        For requests like: "We need a PCI DSS compliance scan"
        """
        print("📋 COMPLIANCE-FOCUSED SCAN WORKFLOW")
        print("=" * 50)
        print("Modules orchestrated:")
        print("1. perform_security_scan(scan_type='full')")
        print("2. Filter results by compliance requirements")
        print("3. Map findings to compliance controls")
        print("4. export_as_html(include_charts=True)")
        print("5. generate_remediation_plan(timeline_days=90)")
        
        print("\n📊 Running compliance-focused security scan...")
        
        # Workflow steps
        print("   → Performing comprehensive security scan...")
        print("   → Mapping findings to PCI DSS requirements...")
        print("   → Identifying compliance gaps...")
        print("   → Generating audit-ready report...")
        
        return """
✅ PCI DSS Compliance Scan Complete

COMPLIANCE STATUS: NON-COMPLIANT

CRITICAL GAPS:
Requirement 2.1: ❌ Default passwords found on 2 devices
Requirement 2.3: ❌ Unencrypted protocols in use (Telnet, FTP)
Requirement 4.1: ❌ Cardholder data transmitted unencrypted
Requirement 6.2: ⚠️ 5 systems missing critical patches

PASSING CONTROLS:
Requirement 1.1: ✅ Firewall configuration standards
Requirement 8.1: ✅ User identification management
Requirement 10.1: ✅ Audit trails implemented

REMEDIATION TIMELINE:
- Critical items: Must fix within 30 days
- High priority: Fix within 60 days
- Medium priority: Fix within 90 days

Full HTML report generated: pci_compliance_report.html
"""
    
    async def incident_response_scan(self, request: str) -> str:
        """
        Workflow 5: Incident Response Security Scan
        For requests like: "We think we've been compromised, help!"
        """
        print("🚨 INCIDENT RESPONSE SCAN WORKFLOW")
        print("=" * 50)
        print("Modules orchestrated:")
        print("1. scan_tcp_range(1-65535) - Full port scan")
        print("2. detect_services_batch() - All open ports")
        print("3. Check for unusual services/backdoors")
        print("4. compare_scan_results() with baseline")
        print("5. export_as_json() for SIEM integration")
        
        print("\n🔴 INITIATING INCIDENT RESPONSE SCAN...")
        print("⚠️  This is a more aggressive scan for incident response")
        
        # Workflow steps
        print("   → Running full port scan (all 65535 ports)...")
        print("   → Detecting all running services...")
        print("   → Comparing with baseline configuration...")
        print("   → Identifying anomalies...")
        print("   → Generating incident report...")
        
        return """
🚨 INCIDENT RESPONSE SCAN RESULTS

SUSPICIOUS FINDINGS:
1. Unusual service on port 31337 (common backdoor port)
2. New SSH service on port 2222 (not in baseline)
3. IRC client connection on port 6667 (possible C&C)
4. Unknown service on port 55555 sending data

BASELINE DEVIATIONS:
- 4 new ports opened since last scan
- 2 services running with different versions
- Network traffic to suspicious IP ranges

IMMEDIATE ACTIONS:
1. ISOLATE affected systems from network
2. CAPTURE memory dump for forensics
3. BLOCK outbound traffic to suspicious IPs
4. PRESERVE logs and evidence
5. INITIATE incident response procedure

Evidence package created: incident_20240115_142532.json
Alert sent to security team.
"""
    
    def demonstrate_dynamic_workflow_creation(self):
        """
        Show how Claude Code can create custom workflows on the fly.
        """
        print("\n" + "=" * 80)
        print("DYNAMIC WORKFLOW CREATION")
        print("=" * 80)
        
        print("\nIT Professional: 'I need to check if our web servers are vulnerable")
        print("                 to Log4j, and also verify they have valid SSL certs'")
        
        print("\n🤖 Claude Code: I'll create a custom workflow for your specific needs:")
        
        print("\nCustom Workflow - Log4j + SSL Check:")
        print("```python")
        print("async def custom_log4j_ssl_check(targets: List[str]):")
        print("    results = {}")
        print("    ")
        print("    for target in targets:")
        print("        # Step 1: Scan web ports")
        print("        web_ports = scan_tcp_ports_batch(target, [80, 443, 8080, 8443])")
        print("        ")
        print("        # Step 2: Detect services and versions")
        print("        services = detect_services_batch(target, ")
        print("            [p['port'] for p in web_ports if p['state'] == 'open'])")
        print("        ")
        print("        # Step 3: Check for Log4j vulnerability")
        print("        for service in services:")
        print("            if 'java' in service.get('banner', '').lower():")
        print("                log4j_cves = search_cve_by_id('CVE-2021-44228')")
        print("                # Additional Log4j-specific checks...")
        print("        ")
        print("        # Step 4: Validate SSL certificates")
        print("        ssl_ports = [443, 8443]")
        print("        for port in ssl_ports:")
        print("            if port in [p['port'] for p in web_ports if p['state'] == 'open']:")
        print("                cert_check = check_ssl_certificate(target, port)")
        print("                results[f'{target}:{port}'] = cert_check")
        print("    ")
        print("    return results")
        print("```")
        
        print("\nThis custom workflow combines multiple security checks specifically")
        print("for your Log4j + SSL verification needs.")


async def main():
    """Run security workflow demonstrations."""
    
    orchestrator = SecurityWorkflowOrchestrator()
    
    # Example requests from IT professionals
    requests = [
        "Give me a quick security check of our main server",
        "Can you assess our web application for vulnerabilities?",
        "We need to audit our database security",
        "Run a PCI compliance scan on our payment systems",
        "Help! We think we've been hacked - need immediate scan"
    ]
    
    print("SUPERSLEUTH SECURITY WORKFLOWS - Claude Code Orchestration")
    print("=" * 80)
    print("\nDemonstrating how Claude Code interprets requests and")
    print("orchestrates security modules to create custom workflows.\n")
    
    # Process each request
    for i, request in enumerate(requests, 1):
        print(f"\n{'='*80}")
        print(f"Request {i}: \"{request}\"")
        print(f"{'='*80}")
        
        result = await orchestrator.interpret_request(request)
        print(result)
        
        if i < len(requests):
            print("\nPress Enter to continue to next example...")
            input()
    
    # Show dynamic workflow creation
    orchestrator.demonstrate_dynamic_workflow_creation()
    
    print("\n" + "=" * 80)
    print("KEY INSIGHTS FOR IT PROFESSIONALS")
    print("=" * 80)
    print("\n1. Natural Language → Workflow: Claude Code interprets your request")
    print("   and automatically selects the right security modules")
    print("\n2. Modular Approach: Each function can be used independently or")
    print("   combined into complex workflows")
    print("\n3. Safety First: All scans are designed to be non-intrusive and")
    print("   require proper authorization")
    print("\n4. Customizable: Claude Code can create new workflows on the fly")
    print("   based on your specific needs")
    print("\n5. Integration Ready: Results can be exported in various formats")
    print("   for integration with other tools")


if __name__ == "__main__":
    asyncio.run(main())