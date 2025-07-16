"""
SuperSleuth Network - Main integration module
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from .diagnostic import DiagnosticSuite, AdaptiveDiagnosticBrain
from .authorization import EnterpriseAuthorization, AuthorizationRequest, RiskLevel
from ..diagnostics.network_discovery import NetworkDiscovery
from ..diagnostics.performance_analysis import PerformanceAnalysis
from ..diagnostics.wifi_analysis import WiFiAnalysis
from ..diagnostics.security_assessment import SecurityAssessment
from ..reporting.report_generator import SuperSleuthReportGenerator, validate_report_quality
from ..utils.logger import get_logger, get_audit_logger


class SuperSleuthNetwork:
    """
    Main SuperSleuth Network class that orchestrates all diagnostic capabilities
    """
    
    def __init__(self, client_config: Dict[str, Any], technician_profile: Dict[str, Any]):
        """
        Initialize SuperSleuth Network
        
        Args:
            client_config: Client configuration including name, SOW, compliance requirements
            technician_profile: IT technician profile including skill level
        """
        self.client_config = client_config
        self.technician_profile = technician_profile
        self.logger = get_logger("SuperSleuthNetwork")
        self.audit_logger = get_audit_logger(client_config['client_name'])
        self.authorization = EnterpriseAuthorization(client_config)
        self.diagnostic_brain = AdaptiveDiagnosticBrain()
        self.session_id = self._generate_session_id()
        
        # Track session state
        self.diagnostics_run = []
        self.findings = {}
        self.reports_generated = []
        
        self.logger.info(f"SuperSleuth Network session {self.session_id} initialized")
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"SSN-{self.client_config['client_name'][:3].upper()}-{timestamp}"
    
    def start_diagnostic_session(self, issue_description: str) -> Dict[str, Any]:
        """
        Start an interactive diagnostic session
        
        Args:
            issue_description: Description of the network issue
            
        Returns:
            Session information and initial diagnostic plan
        """
        self.logger.info(f"Starting diagnostic session for: {issue_description}")
        
        # Display collaboration message
        print(f"""
🤝 SUPERSLEUTH COLLABORATION SESSION STARTING
===========================================

🧠 AI BRAIN: Ready to assist with network diagnostics
👤 TECHNICIAN: {self.technician_profile['name']} ({self.technician_profile['skill_level']})
🎯 ISSUE: {issue_description}

🔧 BUILDING CUSTOM DIAGNOSTIC TOOLKIT...
Based on your description, I'm creating these tools:

1. 📡 Network Signal Analyzer (tailored for "{issue_description}")
2. 🔍 Device Discovery Tool (configured for your environment)
3. 📊 Performance Monitor (adapted to your skill level)
4. 🛠️ Automated Fix Generator (will create based on findings)

💬 HOW WE'LL WORK TOGETHER:
- I'll create and run diagnostic tools
- You'll provide on-site observations and execute recommendations  
- I'll interpret results and guide next steps
- Together we'll build solutions specific to this network

🚀 Ready to begin? I'll start with network discovery.
   You can type 'explain' at any time for more details on what I'm doing.
        """)
        
        # Build initial diagnostic plan
        diagnostic_plan = self._build_diagnostic_plan(issue_description)
        
        return {
            'session_id': self.session_id,
            'status': 'active',
            'diagnostic_plan': diagnostic_plan,
            'next_step': diagnostic_plan[0] if diagnostic_plan else None
        }
    
    def _build_diagnostic_plan(self, issue_description: str) -> List[Dict[str, Any]]:
        """Build customized diagnostic plan based on issue description"""
        
        plan = []
        
        # Always start with network discovery
        plan.append({
            'diagnostic': 'network_discovery',
            'reason': 'Establish baseline of network devices and topology',
            'estimated_time': '2-5 minutes',
            'authorization_required': True
        })
        
        # Add diagnostics based on issue keywords
        issue_lower = issue_description.lower()
        
        if any(word in issue_lower for word in ['slow', 'performance', 'speed', 'latency']):
            plan.append({
                'diagnostic': 'performance_analysis',
                'reason': 'Measure network performance and identify bottlenecks',
                'estimated_time': '5-10 minutes',
                'authorization_required': True
            })
        
        if any(word in issue_lower for word in ['wifi', 'wireless', 'signal', 'coverage']):
            plan.append({
                'diagnostic': 'wifi_analysis',
                'reason': 'Analyze WiFi infrastructure and signal coverage',
                'estimated_time': '3-5 minutes',
                'authorization_required': True
            })
        
        if any(word in issue_lower for word in ['security', 'breach', 'vulnerable', 'compliance']):
            plan.append({
                'diagnostic': 'security_assessment',
                'reason': 'Assess security posture and compliance status',
                'estimated_time': '10-15 minutes',
                'authorization_required': True
            })
        
        # If no specific keywords, run comprehensive assessment
        if len(plan) == 1:
            plan.extend([
                {
                    'diagnostic': 'performance_analysis',
                    'reason': 'General performance baseline',
                    'estimated_time': '5-10 minutes',
                    'authorization_required': True
                },
                {
                    'diagnostic': 'security_assessment',
                    'reason': 'Basic security assessment',
                    'estimated_time': '5-10 minutes',
                    'authorization_required': True
                }
            ])
        
        return plan
    
    def run_diagnostic(self, diagnostic_type: str, **kwargs) -> Dict[str, Any]:
        """
        Run a specific diagnostic with proper authorization
        
        Args:
            diagnostic_type: Type of diagnostic to run
            **kwargs: Additional parameters for the diagnostic
            
        Returns:
            Diagnostic results
        """
        self.logger.info(f"Preparing to run {diagnostic_type} diagnostic")
        
        # Create diagnostic instance
        diagnostic = self._create_diagnostic(diagnostic_type, **kwargs)
        if not diagnostic:
            return {
                'error': f'Unknown diagnostic type: {diagnostic_type}',
                'status': 'failed'
            }
        
        # Get authorization requirements
        auth_requirements = diagnostic.get_authorization_required()
        
        # Create authorization request
        auth_request = AuthorizationRequest(
            client_name=self.client_config['client_name'],
            sow_reference=self.client_config['sow_reference'],
            action=f"Run {diagnostic_type} diagnostic",
            scope=self.client_config.get('authorized_scope', 'Local network'),
            risk_level=RiskLevel(auth_requirements.get('risk_level', 'low')),
            business_justification=f"Diagnose reported issue: {kwargs.get('issue_description', 'Network problems')}",
            systems_affected=self.client_config.get('authorized_subnets', []),
            data_access_level=auth_requirements.get('data_access', 'metadata_only'),
            execution_window=f"{datetime.now().strftime('%Y-%m-%d %H:%M')} EST",
            estimated_duration=15,
            rollback_plan="No changes will be made - read-only diagnostic"
        )
        
        # Request authorization
        auth_prompt = self.authorization.request_authorization(auth_request)
        print(auth_prompt)
        
        # In real implementation, would wait for user input
        # For now, simulate approval
        auth_approved = True  # This would come from user input
        
        if not auth_approved:
            return {
                'error': 'Authorization denied',
                'status': 'aborted'
            }
        
        # Run diagnostic in suite
        suite = DiagnosticSuite(self.client_config, self.audit_logger)
        suite.add_diagnostic(diagnostic)
        
        print(f"\n🔄 Running {diagnostic_type} diagnostic...")
        results = suite.execute()
        
        # Process results with adaptive brain
        if results['results']:
            diagnostic_result = results['results'][0]
            self.diagnostic_brain.process_new_data({
                'diagnostic_type': diagnostic_type,
                'status': diagnostic_result.get('status'),
                'findings': diagnostic_result.get('results', {})
            })
            
            # Store results
            self.findings[diagnostic_type] = diagnostic_result
            self.diagnostics_run.append(diagnostic_type)
        
        return results
    
    def _create_diagnostic(self, diagnostic_type: str, **kwargs) -> Optional[BaseDiagnostic]:
        """Create diagnostic instance based on type"""
        
        config = kwargs.get('config', {})
        
        if diagnostic_type == 'network_discovery':
            return NetworkDiscovery(
                config=config,
                authorized_subnets=self.client_config.get('authorized_subnets', ['192.168.1.0/24'])
            )
        
        elif diagnostic_type == 'performance_analysis':
            return PerformanceAnalysis(
                config=config,
                sla_thresholds=kwargs.get('sla_thresholds')
            )
        
        elif diagnostic_type == 'wifi_analysis':
            return WiFiAnalysis(config=config)
        
        elif diagnostic_type == 'security_assessment':
            return SecurityAssessment(
                config=config,
                compliance_frameworks=self.client_config.get('compliance_requirements', ['SOC2'])
            )
        
        return None
    
    def generate_report(self, audience: str = 'it_professional') -> str:
        """
        Generate report for specified audience
        
        Args:
            audience: Target audience (technical, it_professional, business)
            
        Returns:
            Generated report content
        """
        self.logger.info(f"Generating {audience} report")
        
        # Prepare diagnostic data
        diagnostic_data = {}
        for diag_type, result in self.findings.items():
            diagnostic_data[diag_type] = result
        
        # Create report generator
        report_generator = SuperSleuthReportGenerator(
            diagnostic_data=diagnostic_data,
            client_config=self.client_config
        )
        
        # Generate appropriate report
        if audience == 'technical':
            report = report_generator.generate_technical_report()
        elif audience == 'it_professional':
            report = report_generator.generate_it_professional_report()
        elif audience == 'business':
            report = report_generator.generate_client_report()
        else:
            report = report_generator.generate_it_professional_report()
        
        # Validate report quality
        quality_check = validate_report_quality(report, audience)
        
        self.logger.info(
            f"Report generated for {audience} audience. "
            f"Quality score: {quality_check['quality_score']:.1f}%"
        )
        
        # Store report
        self.reports_generated.append({
            'audience': audience,
            'timestamp': datetime.now().isoformat(),
            'quality_score': quality_check['quality_score']
        })
        
        return report
    
    def save_report(self, report: str, audience: str) -> str:
        """Save report to file"""
        
        # Create reports directory
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{self.session_id}_{audience}_{timestamp}.md"
        filepath = reports_dir / filename
        
        # Save report
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.logger.info(f"Report saved to {filepath}")
        
        return str(filepath)
    
    def get_recommendations(self) -> List[str]:
        """Get consolidated recommendations from all diagnostics"""
        
        recommendations = []
        
        for diag_type, result in self.findings.items():
            if 'recommendations' in result:
                recommendations.extend(result['recommendations'])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def get_next_steps(self) -> Dict[str, Any]:
        """Get AI-recommended next steps based on findings"""
        
        next_steps = self.diagnostic_brain.build_next_diagnostic_step()
        
        # Add specific recommendations based on findings
        if self.findings:
            # Check if we found critical issues
            critical_issues = []
            for result in self.findings.values():
                if 'errors' in result and result['errors']:
                    critical_issues.extend(result['errors'])
            
            if critical_issues:
                next_steps['immediate_actions'] = [
                    "Address critical issues found during diagnostics",
                    "Review security vulnerabilities if any were detected",
                    "Implement recommended fixes in priority order"
                ]
        
        return next_steps
    
    def end_session(self) -> Dict[str, Any]:
        """End diagnostic session and provide summary"""
        
        self.logger.info(f"Ending diagnostic session {self.session_id}")
        
        # Generate session summary
        summary = {
            'session_id': self.session_id,
            'duration': 'Variable',  # Would calculate from actual timestamps
            'diagnostics_run': self.diagnostics_run,
            'reports_generated': self.reports_generated,
            'total_recommendations': len(self.get_recommendations()),
            'overall_health_score': self._calculate_overall_health_score(),
            'next_steps': self.get_next_steps()
        }
        
        # Close audit logger
        self.audit_logger.close()
        
        print(f"""
🏁 SUPERSLEUTH SESSION COMPLETE
==============================

Session ID: {summary['session_id']}
Diagnostics Run: {', '.join(summary['diagnostics_run'])}
Overall Health Score: {summary['overall_health_score']}/100
Total Recommendations: {summary['total_recommendations']}

📋 Reports Generated:
{self._format_reports_list()}

🎯 Next Steps:
{self._format_next_steps(summary['next_steps'])}

Thank you for using SuperSleuth Network!
For support, reference session ID: {summary['session_id']}
        """)
        
        return summary
    
    def _calculate_overall_health_score(self) -> int:
        """Calculate overall network health score from all diagnostics"""
        
        scores = []
        
        # Extract scores from different diagnostics
        for diag_type, result in self.findings.items():
            if 'results' in result:
                results = result['results']
                
                # Performance score
                if 'overall_score' in results:
                    scores.append(results['overall_score'])
                
                # Security score (invert risk score)
                elif 'overall_risk_score' in results:
                    scores.append(100 - results['overall_risk_score'])
        
        return int(sum(scores) / len(scores)) if scores else 50
    
    def _format_reports_list(self) -> str:
        """Format list of generated reports"""
        
        if not self.reports_generated:
            return "- No reports generated yet"
        
        lines = []
        for report in self.reports_generated:
            lines.append(
                f"- {report['audience'].title()} Report "
                f"(Quality: {report['quality_score']:.0f}%)"
            )
        
        return '\n'.join(lines)
    
    def _format_next_steps(self, next_steps: Dict[str, Any]) -> str:
        """Format next steps for display"""
        
        lines = []
        
        if 'immediate_actions' in next_steps:
            for action in next_steps['immediate_actions'][:3]:
                lines.append(f"- {action}")
        
        if 'recommended_diagnostics' in next_steps:
            lines.append(f"- Consider running: {', '.join(next_steps['recommended_diagnostics'])}")
        
        return '\n'.join(lines) if lines else "- Review generated reports with your team"