#!/usr/bin/env python3
"""
Claude Code Integration for SuperSleuth Network

This module demonstrates how Claude Code orchestrates SuperSleuth tools
based on natural language requests from IT professionals.
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import asyncio
from datetime import datetime

# SuperSleuth imports
from src.diagnostics.dns_diagnostics import DNSDiagnostics
from src.diagnostics.routing_diagnostics import RoutingDiagnostics
from src.diagnostics.dhcp_diagnostics import DHCPDiagnostics
from src.diagnostics.http_diagnostics import HTTPDiagnostics
from src.diagnostics.port_scanner import PortScanner
from src.diagnostics.topology_interference import TopologyInterference
from src.diagnostics.performance_analysis import PerformanceAnalyzer
from src.diagnostics.advanced_diagnostics import AdvancedDiagnostics
from src.diagnostics.security_assessment import SecurityAssessment
from src.core.network_metrics import NetworkMetrics
from src.reporting.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DiagnosticIntent(Enum):
    """Types of diagnostic intents Claude Code can identify"""
    PERFORMANCE = "performance"
    CONNECTIVITY = "connectivity"
    DNS = "dns"
    SECURITY = "security"
    SERVICE_AVAILABILITY = "service_availability"
    NETWORK_MAPPING = "network_mapping"
    GENERAL = "general"


@dataclass
class DiagnosticContext:
    """Context extracted from natural language request"""
    intent: DiagnosticIntent
    targets: List[str]
    symptoms: List[str]
    constraints: List[str]
    timeline: Optional[str]
    affected_users: Optional[str]
    priority: str = "normal"
    additional_info: Dict[str, Any] = None


class ClaudeCodeIntegration:
    """
    Main integration class that orchestrates SuperSleuth tools
    based on natural language understanding
    """
    
    def __init__(self):
        """Initialize Claude Code integration with all diagnostic tools"""
        self.dns_diag = DNSDiagnostics()
        self.routing_diag = RoutingDiagnostics()
        self.dhcp_diag = DHCPDiagnostics()
        self.http_diag = HTTPDiagnostics()
        self.port_scanner = PortScanner()
        self.topology = TopologyInterference()
        self.perf_analyzer = PerformanceAnalyzer()
        self.advanced_diag = AdvancedDiagnostics()
        self.security = SecurityAssessment()
        self.metrics = NetworkMetrics()
        self.report_gen = ReportGenerator()
        
        # Intent patterns for natural language understanding
        self.intent_patterns = {
            DiagnosticIntent.PERFORMANCE: [
                "slow", "performance", "latency", "speed", "timeout",
                "degraded", "lag", "delay", "bandwidth"
            ],
            DiagnosticIntent.CONNECTIVITY: [
                "cannot connect", "unreachable", "connection failed",
                "no access", "blocked", "firewall", "can't reach"
            ],
            DiagnosticIntent.DNS: [
                "dns", "resolution", "domain", "lookup", "resolve",
                "nameserver", "nslookup"
            ],
            DiagnosticIntent.SECURITY: [
                "suspicious", "attack", "breach", "unauthorized",
                "malware", "intrusion", "scan", "vulnerability"
            ],
            DiagnosticIntent.SERVICE_AVAILABILITY: [
                "down", "unavailable", "outage", "not responding",
                "error 503", "service failed", "crashed"
            ],
            DiagnosticIntent.NETWORK_MAPPING: [
                "topology", "map", "discover", "inventory",
                "network layout", "infrastructure"
            ]
        }
    
    def analyze_request(self, request: str) -> DiagnosticContext:
        """
        Analyze natural language request to determine diagnostic context
        
        Args:
            request: Natural language problem description
            
        Returns:
            DiagnosticContext with extracted information
        """
        request_lower = request.lower()
        
        # Determine primary intent
        intent = DiagnosticIntent.GENERAL
        max_matches = 0
        
        for intent_type, patterns in self.intent_patterns.items():
            matches = sum(1 for pattern in patterns if pattern in request_lower)
            if matches > max_matches:
                max_matches = matches
                intent = intent_type
        
        # Extract targets (IPs, hostnames, URLs)
        targets = self._extract_targets(request)
        
        # Extract symptoms
        symptoms = self._extract_symptoms(request)
        
        # Extract constraints
        constraints = self._extract_constraints(request)
        
        # Extract timeline
        timeline = self._extract_timeline(request)
        
        # Extract affected scope
        affected_users = self._extract_affected_users(request)
        
        # Determine priority
        priority = "urgent" if any(word in request_lower for word in 
                                  ["urgent", "critical", "emergency", "asap"]) else "normal"
        
        return DiagnosticContext(
            intent=intent,
            targets=targets,
            symptoms=symptoms,
            constraints=constraints,
            timeline=timeline,
            affected_users=affected_users,
            priority=priority
        )
    
    def _extract_targets(self, request: str) -> List[str]:
        """Extract network targets from request"""
        import re
        
        targets = []
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b'
        targets.extend(re.findall(ip_pattern, request))
        
        # URLs
        url_pattern = r'https?://[^\s]+'
        targets.extend(re.findall(url_pattern, request))
        
        # Hostnames (basic pattern)
        hostname_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'
        potential_hostnames = re.findall(hostname_pattern, request)
        
        # Filter out common words that match hostname pattern
        common_words = {'the', 'and', 'for', 'with', 'from', 'this', 'that', 'have', 'been'}
        targets.extend([h for h in potential_hostnames 
                       if '.' in h and h.lower() not in common_words])
        
        return list(set(targets))  # Remove duplicates
    
    def _extract_symptoms(self, request: str) -> List[str]:
        """Extract symptoms from request"""
        symptoms = []
        
        symptom_patterns = {
            'timeout': r'timeout|timed? out',
            'slow': r'slow|sluggish|poor performance',
            'error': r'error \d+|failed|failure',
            'intermittent': r'intermittent|sometimes|occasionally',
            'packet_loss': r'packet loss|dropping packets|lost packets',
            'high_latency': r'high latency|latency|ping time',
            'connection_reset': r'connection reset|reset|RST'
        }
        
        import re
        for symptom, pattern in symptom_patterns.items():
            if re.search(pattern, request, re.IGNORECASE):
                symptoms.append(symptom)
        
        return symptoms
    
    def _extract_constraints(self, request: str) -> List[str]:
        """Extract operational constraints from request"""
        constraints = []
        
        constraint_patterns = {
            'no_disruption': r'without disrupting|no disruption|production',
            'business_hours': r'business hours|working hours|9.?to.?5',
            'quick_check': r'quick check|brief|fast analysis',
            'compliance': r'compliance|HIPAA|PCI|regulatory'
        }
        
        import re
        for constraint, pattern in constraint_patterns.items():
            if re.search(pattern, request, re.IGNORECASE):
                constraints.append(constraint)
        
        return constraints
    
    def _extract_timeline(self, request: str) -> Optional[str]:
        """Extract timeline information from request"""
        import re
        
        timeline_patterns = [
            r'started? (\w+ \w+)',
            r'since (\w+)',
            r'for the (?:past|last) (\w+)',
            r'(\d+ (?:hours?|days?|weeks?) ago)'
        ]
        
        for pattern in timeline_patterns:
            match = re.search(pattern, request, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_affected_users(self, request: str) -> Optional[str]:
        """Extract affected user scope from request"""
        import re
        
        scope_patterns = [
            r'all users',
            r'(\d+)\+? users',
            r'users in (\w+)',
            r'(\w+ (?:office|branch|department))',
            r'subnet ([0-9./]+)'
        ]
        
        for pattern in scope_patterns:
            match = re.search(pattern, request, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    async def diagnose(self, request: str) -> Dict[str, Any]:
        """
        Main diagnostic method that orchestrates tools based on request
        
        Args:
            request: Natural language problem description
            
        Returns:
            Comprehensive diagnostic results and recommendations
        """
        logger.info(f"Processing request: {request}")
        
        # Analyze request to understand context
        context = self.analyze_request(request)
        logger.info(f"Identified context: {context}")
        
        # Execute diagnostic workflow based on intent
        if context.intent == DiagnosticIntent.PERFORMANCE:
            results = await self._diagnose_performance(context)
        elif context.intent == DiagnosticIntent.CONNECTIVITY:
            results = await self._diagnose_connectivity(context)
        elif context.intent == DiagnosticIntent.DNS:
            results = await self._diagnose_dns(context)
        elif context.intent == DiagnosticIntent.SECURITY:
            results = await self._diagnose_security(context)
        elif context.intent == DiagnosticIntent.SERVICE_AVAILABILITY:
            results = await self._diagnose_service(context)
        elif context.intent == DiagnosticIntent.NETWORK_MAPPING:
            results = await self._map_network(context)
        else:
            results = await self._general_diagnosis(context)
        
        # Generate comprehensive report
        report = self._generate_report(context, results)
        
        return {
            'context': context.__dict__,
            'results': results,
            'report': report,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _diagnose_performance(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute performance diagnostic workflow"""
        results = {}
        
        # 1. Baseline performance metrics
        if context.targets:
            results['baseline'] = {}
            for target in context.targets[:3]:  # Limit to first 3 targets
                try:
                    perf_results = await self.perf_analyzer.analyze_performance(
                        target=target,
                        duration=60 if 'quick_check' in context.constraints else 300
                    )
                    results['baseline'][target] = perf_results
                except Exception as e:
                    logger.error(f"Performance analysis failed for {target}: {e}")
        
        # 2. Check routing paths
        if len(context.targets) >= 2:
            results['routing'] = self.routing_diag.trace_route(
                context.targets[0],
                max_hops=30
            )
        
        # 3. Analyze network metrics
        results['metrics'] = self.metrics.get_current_metrics()
        
        # 4. Check for common performance issues
        results['analysis'] = self._analyze_performance_issues(results)
        
        return results
    
    async def _diagnose_connectivity(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute connectivity diagnostic workflow"""
        results = {}
        
        for target in context.targets:
            target_results = {}
            
            # 1. Basic connectivity test
            target_results['ping'] = self.routing_diag.ping(target)
            
            # 2. Port scan if host is reachable
            if target_results['ping'].get('success'):
                target_results['ports'] = self.port_scanner.scan_common_ports(target)
            
            # 3. Traceroute for path analysis
            target_results['traceroute'] = self.routing_diag.trace_route(target)
            
            # 4. DNS resolution check
            target_results['dns'] = self.dns_diag.resolve(target)
            
            results[target] = target_results
        
        return results
    
    async def _diagnose_dns(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute DNS diagnostic workflow"""
        results = {}
        
        for target in context.targets:
            # Comprehensive DNS testing
            results[target] = self.dns_diag.comprehensive_dns_test(
                domain=target,
                include_dnssec=True,
                test_recursive=True
            )
        
        # Analyze DNS performance patterns
        if context.timeline:
            results['historical'] = self._analyze_dns_history(context.targets)
        
        return results
    
    async def _diagnose_security(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute security diagnostic workflow"""
        results = {}
        
        # 1. Port scanning for unauthorized services
        if context.targets:
            results['port_scan'] = {}
            for target in context.targets:
                scan_result = self.port_scanner.comprehensive_scan(
                    target,
                    stealth='compliance' in context.constraints
                )
                results['port_scan'][target] = scan_result
        
        # 2. Security assessment
        results['security_assessment'] = self.security.assess_security(
            targets=context.targets,
            deep_scan='no_disruption' not in context.constraints
        )
        
        # 3. Traffic analysis if suspicious activity mentioned
        if 'suspicious' in context.symptoms:
            results['traffic_analysis'] = self.advanced_diag.analyze_traffic(
                sources=context.targets,
                duration=3600  # Last hour
            )
        
        return results
    
    async def _diagnose_service(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute service availability diagnostic workflow"""
        results = {}
        
        for target in context.targets:
            service_results = {}
            
            # 1. HTTP/HTTPS testing for web services
            if any(proto in target for proto in ['http://', 'https://', 'www.']):
                service_results['http'] = self.http_diag.comprehensive_http_test(
                    url=target,
                    follow_redirects=True,
                    check_ssl=True
                )
            
            # 2. Port availability
            service_results['ports'] = self.port_scanner.scan_service_ports(target)
            
            # 3. Service response time
            service_results['response_time'] = self.perf_analyzer.measure_response_time(
                target,
                samples=10
            )
            
            results[target] = service_results
        
        return results
    
    async def _map_network(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute network mapping workflow"""
        results = {}
        
        # Use topology interference for network discovery
        if context.targets:
            for target in context.targets:
                if '/' in target:  # Subnet
                    results[target] = self.topology.discover_topology(
                        subnet=target,
                        max_hops=3
                    )
        else:
            # Discover local network
            results['local'] = self.topology.discover_local_topology()
        
        return results
    
    async def _general_diagnosis(self, context: DiagnosticContext) -> Dict[str, Any]:
        """Execute general diagnostic workflow when intent is unclear"""
        results = {}
        
        # Run basic diagnostics for all targets
        for target in context.targets:
            target_results = {}
            
            # Basic connectivity
            target_results['connectivity'] = self.routing_diag.ping(target)
            
            # DNS check
            target_results['dns'] = self.dns_diag.resolve(target)
            
            # Basic performance
            if target_results['connectivity'].get('success'):
                target_results['performance'] = self.perf_analyzer.quick_test(target)
            
            results[target] = target_results
        
        return results
    
    def _analyze_performance_issues(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze performance results to identify common issues"""
        analysis = {
            'issues_found': [],
            'severity': 'low',
            'recommendations': []
        }
        
        # Check for high latency
        for target, metrics in results.get('baseline', {}).items():
            if metrics.get('latency', 0) > 100:
                analysis['issues_found'].append(f"High latency to {target}")
                analysis['severity'] = 'medium'
                analysis['recommendations'].append(
                    f"Investigate routing path to {target}"
                )
        
        # Check for packet loss
        if results.get('metrics', {}).get('packet_loss', 0) > 1:
            analysis['issues_found'].append("Packet loss detected")
            analysis['severity'] = 'high'
            analysis['recommendations'].append(
                "Check network interface errors and cable quality"
            )
        
        return analysis
    
    def _analyze_dns_history(self, domains: List[str]) -> Dict[str, Any]:
        """Analyze historical DNS patterns"""
        # This would typically query historical data
        return {
            'pattern': 'periodic_slowdowns',
            'correlation': 'business_hours',
            'recommendation': 'Consider local DNS caching'
        }
    
    def _generate_report(self, context: DiagnosticContext, 
                        results: Dict[str, Any]) -> str:
        """Generate human-readable report from diagnostic results"""
        report_lines = [
            "# SuperSleuth Network Diagnostic Report",
            f"\n**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Priority**: {context.priority.upper()}",
            f"\n## Request Analysis",
            f"**Intent**: {context.intent.value}",
            f"**Targets**: {', '.join(context.targets)}",
            f"**Symptoms**: {', '.join(context.symptoms)}",
        ]
        
        if context.timeline:
            report_lines.append(f"**Timeline**: {context.timeline}")
        
        if context.affected_users:
            report_lines.append(f"**Affected Users**: {context.affected_users}")
        
        report_lines.append("\n## Diagnostic Results")
        
        # Add results summary based on intent
        if context.intent == DiagnosticIntent.PERFORMANCE:
            self._add_performance_summary(report_lines, results)
        elif context.intent == DiagnosticIntent.CONNECTIVITY:
            self._add_connectivity_summary(report_lines, results)
        elif context.intent == DiagnosticIntent.DNS:
            self._add_dns_summary(report_lines, results)
        elif context.intent == DiagnosticIntent.SECURITY:
            self._add_security_summary(report_lines, results)
        
        # Add recommendations
        report_lines.append("\n## Recommendations")
        recommendations = self._generate_recommendations(context, results)
        for i, rec in enumerate(recommendations, 1):
            report_lines.append(f"{i}. {rec}")
        
        return '\n'.join(report_lines)
    
    def _add_performance_summary(self, lines: List[str], results: Dict[str, Any]):
        """Add performance-specific summary to report"""
        if 'analysis' in results:
            analysis = results['analysis']
            lines.append(f"\n### Performance Analysis")
            lines.append(f"**Severity**: {analysis['severity'].upper()}")
            
            if analysis['issues_found']:
                lines.append("\n**Issues Found**:")
                for issue in analysis['issues_found']:
                    lines.append(f"- {issue}")
    
    def _add_connectivity_summary(self, lines: List[str], results: Dict[str, Any]):
        """Add connectivity-specific summary to report"""
        lines.append("\n### Connectivity Test Results")
        
        for target, target_results in results.items():
            lines.append(f"\n**Target**: {target}")
            
            ping_result = target_results.get('ping', {})
            if ping_result.get('success'):
                lines.append(f"- Ping: ✓ Successful ({ping_result.get('avg_rtt', 'N/A')}ms)")
            else:
                lines.append(f"- Ping: ✗ Failed")
            
            if 'ports' in target_results:
                open_ports = [p for p in target_results['ports'] if p['state'] == 'open']
                lines.append(f"- Open Ports: {len(open_ports)} found")
    
    def _add_dns_summary(self, lines: List[str], results: Dict[str, Any]):
        """Add DNS-specific summary to report"""
        lines.append("\n### DNS Diagnostic Results")
        
        for domain, dns_results in results.items():
            if domain == 'historical':
                continue
                
            lines.append(f"\n**Domain**: {domain}")
            
            if dns_results.get('success'):
                lines.append(f"- Resolution: ✓ Successful")
                lines.append(f"- Response Time: {dns_results.get('response_time', 'N/A')}ms")
                
                if 'records' in dns_results:
                    lines.append(f"- A Records: {', '.join(dns_results['records'].get('A', []))}")
            else:
                lines.append(f"- Resolution: ✗ Failed")
                lines.append(f"- Error: {dns_results.get('error', 'Unknown error')}")
    
    def _add_security_summary(self, lines: List[str], results: Dict[str, Any]):
        """Add security-specific summary to report"""
        lines.append("\n### Security Assessment Results")
        
        if 'security_assessment' in results:
            assessment = results['security_assessment']
            
            if assessment.get('vulnerabilities'):
                lines.append("\n**⚠️ VULNERABILITIES FOUND**:")
                for vuln in assessment['vulnerabilities']:
                    lines.append(f"- {vuln}")
            else:
                lines.append("\n**✓ No immediate vulnerabilities detected**")
    
    def _generate_recommendations(self, context: DiagnosticContext, 
                                 results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on results"""
        recommendations = []
        
        # Performance recommendations
        if context.intent == DiagnosticIntent.PERFORMANCE:
            if results.get('analysis', {}).get('severity') == 'high':
                recommendations.append(
                    "Immediate investigation required - consider escalating to network team"
                )
            recommendations.append(
                "Monitor affected systems continuously for pattern identification"
            )
        
        # Security recommendations
        if context.intent == DiagnosticIntent.SECURITY:
            if results.get('security_assessment', {}).get('vulnerabilities'):
                recommendations.append(
                    "URGENT: Isolate affected systems and initiate incident response"
                )
                recommendations.append(
                    "Review firewall rules and access controls"
                )
        
        # General recommendations
        if context.priority == 'urgent':
            recommendations.insert(0, "Given the urgent priority, consider parallel remediation efforts")
        
        if not recommendations:
            recommendations.append("Continue monitoring and establish baseline metrics")
        
        return recommendations


# Example usage
async def main():
    """Example of using Claude Code integration"""
    claude = ClaudeCodeIntegration()
    
    # Example 1: Performance issue
    request1 = "The company website www.example.com is loading very slowly for users in the Boston office. This started yesterday afternoon."
    
    print("Processing request:", request1)
    results1 = await claude.diagnose(request1)
    print("\nReport:")
    print(results1['report'])
    
    # Example 2: Security concern
    request2 = "URGENT: Detected suspicious outbound traffic from server 192.168.1.50 to unknown external IPs on port 6667"
    
    print("\n" + "="*80 + "\n")
    print("Processing request:", request2)
    results2 = await claude.diagnose(request2)
    print("\nReport:")
    print(results2['report'])


if __name__ == "__main__":
    asyncio.run(main())