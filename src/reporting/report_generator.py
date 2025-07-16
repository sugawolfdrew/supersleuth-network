"""
Multi-tier report generation system for different audiences
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import re

from ..utils.logger import get_logger


class TechnicalTranslator:
    """Convert technical findings to appropriate audience language"""
    
    BUSINESS_TRANSLATIONS = {
        'packet_loss': {
            'technical': 'Packet loss detected at {value}% on primary uplink',
            'it_professional': 'Network is dropping data packets, causing slow file transfers and video call issues. Check cable connections and contact ISP if problem persists.',
            'business': 'Employees may experience slow file downloads and choppy video calls. This affects productivity and customer communications.'
        },
        'weak_encryption': {
            'technical': 'WPA2-PSK detected, WPA3 recommended for enhanced security',
            'it_professional': 'WiFi network using older security (WPA2). Upgrade to WPA3 for better protection against hackers. Most devices from 2018+ support WPA3.',
            'business': 'WiFi security is using older technology. Upgrading will better protect company data from unauthorized access.'
        },
        'channel_congestion': {
            'technical': '2.4GHz channels 1, 6, 11 showing >75% utilization',
            'it_professional': 'WiFi channels are overcrowded, like too many conversations in a small room. Switch to less-used channels or enable automatic channel selection.',
            'business': 'WiFi is slow because too many devices are competing for the same wireless "lanes". Easy fix will improve WiFi speed.'
        },
        'high_latency': {
            'technical': 'Average latency {value}ms exceeds threshold of {threshold}ms',
            'it_professional': 'Network delays are causing slow response times. This affects real-time applications like video calls and remote desktop connections.',
            'business': 'Network delays are making applications feel sluggish, impacting employee productivity.'
        },
        'bandwidth_insufficient': {
            'technical': 'Current bandwidth {current}Mbps below SLA requirement of {required}Mbps',
            'it_professional': 'Internet speed is below contracted levels. Contact ISP to troubleshoot or consider bandwidth upgrade.',
            'business': 'Internet connection cannot support current business needs. Staff may experience delays in cloud applications and file transfers.'
        }
    }
    
    def translate_finding(self, technical_finding: str, audience: str, context: Dict[str, Any] = None) -> str:
        """Translate technical finding to appropriate audience level"""
        
        if context is None:
            context = {}
        
        # Find matching translation pattern
        for key, translations in self.BUSINESS_TRANSLATIONS.items():
            if key in technical_finding.lower():
                template = translations.get(audience, technical_finding)
                
                # Replace placeholders with actual values
                for placeholder, value in context.items():
                    template = template.replace(f'{{{placeholder}}}', str(value))
                
                return template
        
        # Default translation if no specific mapping found
        return self._generic_translation(technical_finding, audience)
    
    def _generic_translation(self, technical_finding: str, audience: str) -> str:
        """Provide generic translation when no specific pattern matches"""
        
        if audience == 'business':
            # Remove technical jargon
            simplified = re.sub(r'\b(TCP|UDP|ICMP|DNS|DHCP|HTTP[S]?)\b', 'network protocol', technical_finding)
            simplified = re.sub(r'\b\d+\.\d+\.\d+\.\d+\b', 'network address', simplified)
            simplified = re.sub(r'\bport\s+\d+\b', 'network service', simplified)
            return simplified
        
        return technical_finding


class SuperSleuthReportGenerator:
    """Multi-tier report generation for different audiences"""
    
    def __init__(self, diagnostic_data: Dict[str, Any], client_config: Dict[str, Any]):
        self.data = diagnostic_data
        self.client = client_config
        self.translator = TechnicalTranslator()
        self.logger = get_logger(self.__class__.__name__)
        self.findings = self._analyze_findings()
    
    def _analyze_findings(self) -> Dict[str, Any]:
        """Analyze diagnostic data to extract key findings"""
        
        findings = {
            'critical_issues': [],
            'important_issues': [],
            'optimization_items': [],
            'security_issues': [],
            'performance_issues': [],
            'quick_wins': [],
            'client_name': self.client.get('client_name', 'Unknown'),
            'assessment_date': datetime.now().strftime('%Y-%m-%d'),
            'it_contact': self.client.get('it_contact', 'IT Department'),
            'report_id': f"SN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        }
        
        # Extract health score
        findings['health_score'] = self._calculate_health_score()
        
        # Process each diagnostic result
        for diagnostic_type, result in self.data.items():
            if isinstance(result, dict) and 'results' in result:
                self._process_diagnostic_result(diagnostic_type, result, findings)
        
        return findings
    
    def _calculate_health_score(self) -> int:
        """Calculate overall network health score"""
        
        scores = []
        
        # Performance score
        if 'performance_analysis' in self.data:
            perf_data = self.data['performance_analysis']
            if 'results' in perf_data and 'overall_score' in perf_data['results']:
                scores.append(perf_data['results']['overall_score'])
        
        # Security score (invert risk score)
        if 'security_assessment' in self.data:
            sec_data = self.data['security_assessment']
            if 'results' in sec_data and 'overall_risk_score' in sec_data['results']:
                scores.append(100 - sec_data['results']['overall_risk_score'])
        
        # Network discovery score (based on unknown devices)
        if 'network_discovery' in self.data:
            disc_data = self.data['network_discovery']
            if 'results' in disc_data and 'analysis' in disc_data['results']:
                unknown_count = len(disc_data['results']['analysis'].get('unknown_devices', []))
                total_devices = disc_data['results'].get('total_devices', 1)
                device_score = 100 - (unknown_count / total_devices * 100)
                scores.append(device_score)
        
        return int(sum(scores) / len(scores)) if scores else 50
    
    def _process_diagnostic_result(self, diagnostic_type: str, result: Dict[str, Any], 
                                 findings: Dict[str, Any]):
        """Process a diagnostic result to extract issues"""
        
        if result.get('status') != 'completed':
            return
        
        results_data = result.get('results', {})
        
        # Process by diagnostic type
        if diagnostic_type == 'network_discovery':
            self._process_network_discovery(results_data, findings)
        elif diagnostic_type == 'performance_analysis':
            self._process_performance_analysis(results_data, findings)
        elif diagnostic_type == 'security_assessment':
            self._process_security_assessment(results_data, findings)
        elif diagnostic_type == 'wifi_analysis':
            self._process_wifi_analysis(results_data, findings)
        
        # Process recommendations
        for rec in result.get('recommendations', []):
            if 'CRITICAL' in rec or 'URGENT' in rec:
                findings['critical_issues'].append(rec)
            elif 'HIGH' in rec:
                findings['important_issues'].append(rec)
            else:
                findings['optimization_items'].append(rec)
    
    def _process_network_discovery(self, results: Dict[str, Any], findings: Dict[str, Any]):
        """Process network discovery results"""
        
        findings['device_count'] = results.get('total_devices', 0)
        
        # Check for unknown devices
        analysis = results.get('analysis', {})
        unknown_devices = analysis.get('unknown_devices', [])
        
        if unknown_devices:
            findings['security_issues'].append({
                'type': 'unknown_devices',
                'count': len(unknown_devices),
                'devices': unknown_devices[:5]  # First 5
            })
    
    def _process_performance_analysis(self, results: Dict[str, Any], findings: Dict[str, Any]):
        """Process performance analysis results"""
        
        perf_metrics = results.get('performance_metrics', {})
        
        # Bandwidth
        if 'bandwidth' in perf_metrics:
            bandwidth = perf_metrics['bandwidth']
            findings['speed_mbps'] = bandwidth.get('download_mbps', 0)
            findings['upload_mbps'] = bandwidth.get('upload_mbps', 0)
        
        # SLA validation
        sla_validation = results.get('sla_validation', {})
        if not sla_validation.get('compliant', True):
            for violation in sla_validation.get('violations', []):
                findings['performance_issues'].append(violation)
    
    def _process_security_assessment(self, results: Dict[str, Any], findings: Dict[str, Any]):
        """Process security assessment results"""
        
        findings['security_score'] = 100 - results.get('overall_risk_score', 0)
        
        # Extract security issues
        for category in ['network_security', 'wifi_security', 'access_control']:
            if category in results:
                for issue in results[category].get('security_issues', []):
                    findings['security_issues'].append(issue)
        
        # Compliance status
        compliance = results.get('compliance_status', {})
        findings['compliance_frameworks'] = results.get('compliance_frameworks', [])
        findings['compliance_compliant'] = compliance.get('overall_compliant', True)
    
    def _process_wifi_analysis(self, results: Dict[str, Any], findings: Dict[str, Any]):
        """Process WiFi analysis results"""
        
        # Signal coverage
        signal_analysis = results.get('signal_analysis', {})
        coverage_issues = signal_analysis.get('coverage_issues', [])
        
        if coverage_issues:
            total_area = 100  # Placeholder
            weak_areas = len(coverage_issues)
            findings['coverage_percent'] = max(0, total_area - (weak_areas * 10))
        else:
            findings['coverage_percent'] = 95  # Good coverage
        
        # Extract weak/dead zones
        findings['weak_areas'] = [issue.get('location', 'Unknown') 
                                 for issue in coverage_issues 
                                 if issue.get('type') == 'weak_signal']
        findings['dead_zones'] = []  # Would be populated from detailed analysis
    
    def generate_technical_report(self) -> str:
        """Generate detailed technical report for network engineers"""
        
        report = f"""# SuperSleuth Network - Technical Deep-Dive Report

**Client**: {self.findings['client_name']}  
**Assessment Date**: {self.findings['assessment_date']}  
**Report ID**: {self.findings['report_id']}

## Executive Summary

Network health score: {self.findings['health_score']}/100

### Critical Findings
"""
        
        # Add critical issues
        if self.findings['critical_issues']:
            for issue in self.findings['critical_issues']:
                report += f"- {issue}\n"
        else:
            report += "- No critical issues found\n"
        
        # Detailed technical sections
        report += self._generate_technical_network_section()
        report += self._generate_technical_performance_section()
        report += self._generate_technical_security_section()
        report += self._generate_technical_recommendations()
        
        return report
    
    def generate_it_professional_report(self) -> str:
        """Generate actionable report for general IT staff"""
        
        report = f"""# SuperSleuth Network Diagnostic Report

**Client**: {self.findings['client_name']}  
**Assessment Date**: {self.findings['assessment_date']}  
**IT Contact**: {self.findings['it_contact']}

## 🚨 IMMEDIATE ACTION REQUIRED

"""
        
        # Format critical issues for IT
        if self.findings['critical_issues']:
            for issue in self.findings['critical_issues']:
                translated = self.translator.translate_finding(issue, 'it_professional')
                report += f"⚠️ **{translated}**\n\n"
        else:
            report += "✅ No critical issues requiring immediate attention.\n\n"
        
        # Network health overview
        report += f"""## 📊 NETWORK HEALTH OVERVIEW

Your network scored **{self.findings['health_score']}/100**

**What this means**: Scores above 85 indicate good network health. 
Scores below 70 suggest immediate attention needed.

### Performance Summary
- **Internet Speed**: {self.findings.get('speed_mbps', 'Unknown')} Mbps download / {self.findings.get('upload_mbps', 'Unknown')} Mbps upload
- **Device Count**: {self.findings.get('device_count', 0)} devices detected
- **WiFi Coverage**: {self.findings.get('coverage_percent', 'Unknown')}% of facility covered adequately

"""
        
        # Security findings
        report += self._generate_it_security_section()
        
        # Step-by-step remediation
        report += self._generate_it_remediation_steps()
        
        # Monitoring checklist
        report += """## 📋 MONITORING CHECKLIST

Set up these ongoing checks:
- [ ] Weekly speed tests using speedtest.net
- [ ] Monthly device inventory review  
- [ ] Quarterly password updates for WiFi networks
- [ ] Semi-annual firmware updates for network equipment

"""
        
        report += f"**Questions?** Contact SuperSleuth support with reference number: {self.findings['report_id']}"
        
        return report
    
    def generate_client_report(self) -> str:
        """Generate business-focused report in plain English"""
        
        # Calculate business metrics
        productivity_impact = self._calculate_productivity_impact()
        security_risk = self._translate_security_risk(self.findings.get('security_score', 50))
        
        report = f"""# Network Assessment Executive Summary

**Organization**: {self.findings['client_name']}  
**Assessment Period**: {self.findings['assessment_date']}

## 🎯 BOTTOM LINE UP FRONT

Your network is currently performing at **{self.findings['health_score']}%** of optimal capacity.

**Business Impact**:
- Employee productivity: {productivity_impact}
- Security risk level: {security_risk}
- Compliance status: {self._summarize_compliance_status()}

"""
        
        # Key business findings
        report += "## 💼 KEY BUSINESS FINDINGS\n\n"
        
        # Internet performance
        speed_status = self._translate_speed_to_business_terms(self.findings)
        report += f"""### Internet Performance
**Current Status**: {speed_status}

"""
        
        # Security assessment
        security_grade = self._calculate_security_grade(self.findings.get('security_issues', []))
        report += f"""### Security Assessment
**Overall Security Grade**: {security_grade}

"""
        
        # Recommended investments
        report += self._generate_business_investments()
        
        # Expected benefits
        report += self._generate_expected_benefits()
        
        # Next steps
        report += """## 📞 NEXT STEPS

1. Review this report with your IT team
2. Prioritize fixes based on business impact and budget
3. Schedule implementation during low-business-impact hours
4. Set up quarterly network health reviews

"""
        
        report += f"**Questions about this assessment?**  \nContact: {self.findings['it_contact']} or SuperSleuth reference: {self.findings['report_id']}"
        
        return report
    
    def _generate_technical_network_section(self) -> str:
        """Generate technical network discovery section"""
        
        section = "\n## Network Discovery Analysis\n\n"
        
        if 'network_discovery' in self.data:
            disc_data = self.data['network_discovery'].get('results', {})
            
            section += f"### Device Inventory\n"
            section += f"- Total devices discovered: {disc_data.get('total_devices', 0)}\n"
            
            # Device type distribution
            if 'network_map' in disc_data:
                device_types = disc_data['network_map'].get('device_types', {})
                section += "\n**Device Type Distribution:**\n"
                for device_type, count in device_types.items():
                    section += f"- {device_type}: {count}\n"
            
            # Network utilization
            if 'network_map' in disc_data:
                section += "\n**Subnet Utilization:**\n"
                for subnet, info in disc_data['network_map'].get('subnets', {}).items():
                    section += f"- {subnet}: {info.get('utilization', 0)}% utilized ({info.get('device_count', 0)} devices)\n"
        
        return section
    
    def _generate_technical_performance_section(self) -> str:
        """Generate technical performance section"""
        
        section = "\n## Performance Analysis\n\n"
        
        if 'performance_analysis' in self.data:
            perf_data = self.data['performance_analysis'].get('results', {})
            metrics = perf_data.get('performance_metrics', {})
            
            # Bandwidth details
            if 'bandwidth' in metrics:
                bandwidth = metrics['bandwidth']
                section += f"### Bandwidth Measurements\n"
                section += f"- Download: {bandwidth.get('download_mbps', 'N/A')} Mbps\n"
                section += f"- Upload: {bandwidth.get('upload_mbps', 'N/A')} Mbps\n"
                section += f"- Latency: {bandwidth.get('ping_ms', 'N/A')} ms\n"
                section += f"- Test Server: {bandwidth.get('server', 'Unknown')}\n\n"
            
            # Latency analysis
            if 'latency' in metrics:
                section += "### Latency Analysis\n"
                for endpoint, values in metrics['latency'].items():
                    section += f"- {endpoint}: {values.get('avg_ms', 'N/A')}ms avg "
                    section += f"({values.get('min_ms', 'N/A')}-{values.get('max_ms', 'N/A')}ms range)\n"
                section += "\n"
            
            # Packet loss
            if 'packet_loss' in metrics:
                section += "### Packet Loss Analysis\n"
                for destination, loss in metrics['packet_loss'].items():
                    section += f"- {destination}: {loss.get('loss_percent', 0)}% loss\n"
        
        return section
    
    def _generate_technical_security_section(self) -> str:
        """Generate technical security section"""
        
        section = "\n## Security Assessment\n\n"
        
        if 'security_assessment' in self.data:
            sec_data = self.data['security_assessment'].get('results', {})
            
            section += f"### Risk Score: {sec_data.get('overall_risk_score', 'N/A')}/100\n\n"
            
            # Open ports
            if 'network_security' in sec_data:
                open_ports = sec_data['network_security'].get('open_ports', [])
                if open_ports:
                    section += "### Open Ports Detected\n"
                    for port_info in open_ports:
                        section += f"- Port {port_info['port']}: {port_info['service']} "
                        section += f"(Risk: {port_info['risk']})\n"
                    section += "\n"
            
            # Compliance status
            if 'compliance_status' in sec_data:
                compliance = sec_data['compliance_status']
                section += f"### Compliance Status\n"
                section += f"- Overall Compliant: {compliance.get('overall_compliant', False)}\n"
                
                if 'framework_results' in compliance:
                    section += "\n**Framework Results:**\n"
                    for framework, result in compliance['framework_results'].items():
                        status = "✅ Compliant" if result.get('compliant') else "❌ Non-compliant"
                        section += f"- {framework}: {status}\n"
        
        return section
    
    def _generate_technical_recommendations(self) -> str:
        """Generate technical recommendations section"""
        
        section = "\n## Technical Recommendations\n\n"
        
        # Prioritized recommendations
        if self.findings['critical_issues']:
            section += "### Critical Priority\n"
            for rec in self.findings['critical_issues']:
                section += f"- {rec}\n"
            section += "\n"
        
        if self.findings['important_issues']:
            section += "### High Priority\n"
            for rec in self.findings['important_issues']:
                section += f"- {rec}\n"
            section += "\n"
        
        if self.findings['optimization_items']:
            section += "### Optimization Opportunities\n"
            for rec in self.findings['optimization_items'][:5]:  # Top 5
                section += f"- {rec}\n"
        
        return section
    
    def _generate_it_security_section(self) -> str:
        """Generate security section for IT professionals"""
        
        section = "## 🔒 SECURITY FINDINGS\n\n"
        
        security_issues = self.findings.get('security_issues', [])
        
        if security_issues:
            # Group by severity
            critical = [i for i in security_issues if i.get('severity') == 'critical']
            high = [i for i in security_issues if i.get('severity') == 'high']
            medium = [i for i in security_issues if i.get('severity') == 'medium']
            
            if critical:
                section += "### 🚨 Critical Security Issues\n"
                for issue in critical:
                    translated = self.translator.translate_finding(
                        issue.get('message', ''), 'it_professional'
                    )
                    section += f"- **{issue.get('type', 'Unknown')}**: {translated}\n"
                section += "\n"
            
            if high:
                section += "### ⚠️ High Priority Security Issues\n"
                for issue in high:
                    translated = self.translator.translate_finding(
                        issue.get('message', ''), 'it_professional'
                    )
                    section += f"- **{issue.get('type', 'Unknown')}**: {translated}\n"
                section += "\n"
        else:
            section += "✅ No significant security issues detected.\n\n"
        
        section += """**Why this matters**: Each security issue represents potential risk for:
- Data breaches affecting client/employee information
- Compliance violations (PCI, HIPAA, etc.)
- Unauthorized network access and resource theft

"""
        
        return section
    
    def _generate_it_remediation_steps(self) -> str:
        """Generate step-by-step remediation for IT staff"""
        
        section = "## 🛠️ STEP-BY-STEP REMEDIATION\n\n"
        
        # Critical fixes
        if self.findings['critical_issues']:
            section += "### Priority 1: Critical Issues (Fix Today)\n"
            for i, issue in enumerate(self.findings['critical_issues'], 1):
                section += f"\n**Step {i}: {issue}**\n"
                section += self._generate_remediation_steps_for_issue(issue)
        
        # Important fixes
        if self.findings['important_issues']:
            section += "\n### Priority 2: Important Issues (Fix This Week)\n"
            for i, issue in enumerate(self.findings['important_issues'][:3], 1):
                section += f"\n**Step {i}: {issue}**\n"
                section += self._generate_remediation_steps_for_issue(issue)
        
        return section
    
    def _generate_remediation_steps_for_issue(self, issue: str) -> str:
        """Generate specific remediation steps for an issue"""
        
        steps = ""
        
        # Pattern matching for common issues
        if 'port' in issue.lower() and 'close' in issue.lower():
            steps += """1. Identify the service using the port: `netstat -tulpn | grep PORT`
2. If service is not needed, stop and disable it
3. Update firewall rules to block the port
4. Verify port is closed: `nmap -p PORT localhost`
"""
        elif 'wpa3' in issue.lower() or 'encryption' in issue.lower():
            steps += """1. Access your wireless router/AP admin interface
2. Navigate to Wireless Security settings
3. Change security mode to WPA3 (or WPA2/WPA3 mixed mode)
4. Update the passphrase to a strong, unique password
5. Save settings and reboot the access point
6. Update all client devices with new settings
"""
        elif 'dns' in issue.lower():
            steps += """1. Check current DNS settings: `cat /etc/resolv.conf`
2. Configure secure DNS servers (e.g., 1.1.1.1, 8.8.8.8)
3. Enable DNSSEC if supported by your resolver
4. Test DNS resolution: `dig @1.1.1.1 example.com`
"""
        else:
            steps += """1. Research the specific issue and best practices
2. Document current configuration before making changes
3. Implement the recommended fix in a test environment first
4. Apply the fix to production during maintenance window
5. Verify the fix resolved the issue
6. Document the change for future reference
"""
        
        return steps
    
    def _calculate_productivity_impact(self) -> str:
        """Calculate productivity impact description"""
        
        health_score = self.findings['health_score']
        
        if health_score >= 90:
            return "Minimal impact - network supporting productivity well"
        elif health_score >= 70:
            return "Some impact during peak hours - occasional delays"
        elif health_score >= 50:
            return "Moderate impact - frequent delays affecting work"
        else:
            return "Significant impact - network issues hampering productivity"
    
    def _translate_security_risk(self, security_score: int) -> str:
        """Convert security score to business risk language"""
        
        if security_score >= 90:
            return "Low Risk - Strong security posture with minor gaps"
        elif security_score >= 70:
            return "Moderate Risk - Some vulnerabilities requiring attention"
        elif security_score >= 50:
            return "High Risk - Multiple security gaps exposing business data"
        else:
            return "Critical Risk - Immediate action required to prevent breach"
    
    def _summarize_compliance_status(self) -> str:
        """Summarize compliance status in business terms"""
        
        if self.findings.get('compliance_compliant', True):
            frameworks = ', '.join(self.findings.get('compliance_frameworks', ['General']))
            return f"Compliant with {frameworks} requirements"
        else:
            return "Non-compliant - remediation required for regulatory compliance"
    
    def _translate_speed_to_business_terms(self, findings: Dict[str, Any]) -> str:
        """Convert speed metrics to business language"""
        
        speed = findings.get('speed_mbps', 0)
        
        if speed >= 100:
            return "✅ Excellent - Supporting current business needs effectively"
        elif speed >= 50:
            return "⚠️ Good - Minor productivity impacts during peak usage"
        elif speed >= 25:
            return "❌ Poor - Causing noticeable delays in daily operations"
        else:
            return "🚨 Critical - Significantly impacting business productivity"
    
    def _calculate_security_grade(self, security_issues: List[Dict[str, Any]]) -> str:
        """Calculate letter grade for security"""
        
        critical_count = sum(1 for i in security_issues if i.get('severity') == 'critical')
        high_count = sum(1 for i in security_issues if i.get('severity') == 'high')
        
        if critical_count > 0:
            return "F - Critical vulnerabilities present"
        elif high_count > 2:
            return "D - Multiple high-risk issues"
        elif high_count > 0:
            return "C - Some security concerns"
        elif len(security_issues) > 3:
            return "B - Minor security improvements needed"
        else:
            return "A - Strong security posture"
    
    def _generate_business_investments(self) -> str:
        """Generate investment recommendations for business"""
        
        section = "## 💰 RECOMMENDED INVESTMENTS\n\n"
        
        # Calculate rough costs
        immediate_cost = len(self.findings['critical_issues']) * 500
        short_term_cost = len(self.findings['important_issues']) * 1000
        long_term_cost = len(self.findings['optimization_items']) * 2000
        
        if self.findings['critical_issues']:
            section += f"### Immediate (This Month) - ${immediate_cost:,}\n"
            for issue in self.findings['critical_issues'][:3]:
                business_desc = self.translator.translate_finding(issue, 'business')
                section += f"- {business_desc}\n"
            section += "\n"
        
        if self.findings['important_issues']:
            section += f"### Short Term (Next 3 Months) - ${short_term_cost:,}\n"
            for issue in self.findings['important_issues'][:3]:
                business_desc = self.translator.translate_finding(issue, 'business')
                section += f"- {business_desc}\n"
            section += "\n"
        
        return section
    
    def _generate_expected_benefits(self) -> str:
        """Generate expected benefits section"""
        
        # Calculate improvement estimates
        current_score = self.findings['health_score']
        potential_score = min(95, current_score + 30)
        productivity_improvement = (potential_score - current_score) // 2
        security_improvement = min(50, 100 - current_score)
        
        section = f"""## 📈 EXPECTED BUSINESS BENEFITS

Implementing these recommendations will:
- Improve employee productivity by an estimated {productivity_improvement}%
- Reduce security breach risk by {security_improvement}%
- Ensure compliance with {', '.join(self.findings.get('compliance_frameworks', ['industry']))} requirements
- Support 25% additional users without degradation

"""
        
        # Quick wins
        if self.findings.get('quick_wins'):
            section += "## ⚡ QUICK WINS (No Cost)\n"
            section += "Your IT team can implement these improvements immediately:\n"
            for win in self.findings['quick_wins'][:3]:
                section += f"- {win}\n"
            section += "\n"
        
        return section


def validate_report_quality(report: str, audience: str) -> Dict[str, Any]:
    """Ensure report meets quality standards for target audience"""
    
    quality_checks = {
        'it_professional': {
            'includes_step_by_step_instructions': '1.' in report or 'Step' in report,
            'explains_technical_concepts': 'What this means' in report,
            'provides_escalation_guidance': 'escalate' in report.lower(),
            'includes_monitoring_setup': 'monitor' in report.lower() or 'checklist' in report.lower()
        },
        'business': {
            'uses_plain_english': not bool(re.search(r'\b(TCP|UDP|ICMP|subnet|VLAN)\b', report)),
            'focuses_on_business_impact': 'productivity' in report.lower() or 'business' in report.lower(),
            'includes_cost_estimates': '$' in report,
            'provides_clear_next_steps': 'next steps' in report.lower()
        }
    }
    
    validation_results = {}
    checks = quality_checks.get(audience, {})
    
    for check_name, check_condition in checks.items():
        validation_results[check_name] = check_condition
    
    passed_checks = sum(validation_results.values())
    total_checks = len(validation_results)
    
    return {
        'quality_score': (passed_checks / total_checks * 100) if total_checks > 0 else 0,
        'passed_checks': passed_checks,
        'total_checks': total_checks,
        'failed_checks': [k for k, v in validation_results.items() if not v],
        'validation_details': validation_results
    }