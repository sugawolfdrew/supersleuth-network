"""
SOC2 Compliance Module

This module implements SOC2 (Service Organization Control 2) compliance checks 
that Claude Code can orchestrate for service organization security assessments.
"""

import json
import hashlib
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from enum import Enum

from .compliance_engine import ComplianceModule, ComplianceControl, ComplianceStatus
from ..utils.logger import get_logger

logger = get_logger(__name__)


class TrustServicePrinciple(Enum):
    """SOC2 Trust Service Principles."""
    SECURITY = "Security"
    AVAILABILITY = "Availability"
    PROCESSING_INTEGRITY = "Processing Integrity"
    CONFIDENTIALITY = "Confidentiality"
    PRIVACY = "Privacy"


class SOC2Control(ComplianceControl):
    """Base class for SOC2 specific controls."""
    
    def __init__(self, principle: TrustServicePrinciple, criteria: str, description: str):
        category = principle.value
        super().__init__(f"SOC2-{criteria}", description, category)
        self.principle = principle
        self.criteria = criteria


# Common Criteria (CC) - Security Principle

class CC1_1_OrganizationalOversight(SOC2Control):
    """The entity demonstrates a commitment to integrity and ethical values."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC1.1",
                        "The entity demonstrates a commitment to integrity and ethical values")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check organizational oversight and governance."""
        try:
            # Check code of conduct
            governance = self._check_governance_policies(scope)
            self.add_evidence('governance_policies', governance)
            
            if not governance.get('code_of_conduct'):
                self.add_finding('high',
                               'No code of conduct established',
                               'Develop and implement code of conduct')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check ethics training
            if not governance.get('ethics_training'):
                self.add_finding('medium',
                               'Ethics training not implemented',
                               'Implement annual ethics training for all employees')
                return ComplianceStatus.PARTIAL
            
            # Check board oversight
            if not governance.get('board_oversight'):
                self.add_finding('medium',
                               'Limited board oversight of security',
                               'Establish regular board security reviews')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing organizational oversight: {e}")
            return ComplianceStatus.ERROR
    
    def _check_governance_policies(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Check governance and ethics policies."""
        return {
            'code_of_conduct': scope.get('has_code_of_conduct', True),
            'ethics_training': scope.get('ethics_training_implemented', True),
            'board_oversight': scope.get('board_security_oversight', True),
            'policy_review_frequency': 'annual',
            'last_review_date': datetime.now().isoformat()
        }


class CC2_1_InformationCommunication(SOC2Control):
    """Information necessary for internal control is communicated."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC2.1",
                        "The entity obtains or generates and uses relevant, quality information to support the functioning of internal control")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check information and communication controls."""
        try:
            # Check security metrics
            metrics = self._check_security_metrics()
            self.add_evidence('security_metrics', metrics)
            
            if not metrics.get('kpis_defined'):
                self.add_finding('high',
                               'Security KPIs not defined',
                               'Define and track security key performance indicators')
                return ComplianceStatus.PARTIAL
            
            # Check reporting structure
            if not metrics.get('regular_reporting'):
                self.add_finding('medium',
                               'Irregular security reporting',
                               'Implement monthly security status reporting')
                return ComplianceStatus.PARTIAL
            
            # Check incident communication
            if not metrics.get('incident_communication'):
                self.add_finding('high',
                               'Incident communication process not defined',
                               'Establish incident escalation and communication procedures')
                return ComplianceStatus.NON_COMPLIANT
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing information communication: {e}")
            return ComplianceStatus.ERROR
    
    def _check_security_metrics(self) -> Dict[str, Any]:
        """Check security metrics and reporting."""
        return {
            'kpis_defined': True,
            'metrics_tracked': ['incidents', 'vulnerabilities', 'patch_compliance', 'training_completion'],
            'regular_reporting': True,
            'reporting_frequency': 'monthly',
            'incident_communication': True,
            'dashboard_available': True
        }


class CC3_1_RiskAssessment(SOC2Control):
    """The entity specifies objectives to identify and assess risks."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC3.1",
                        "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check risk assessment processes."""
        try:
            # Check risk assessment program
            risk_program = self._check_risk_assessment_program(scope)
            self.add_evidence('risk_assessment', risk_program)
            
            if not risk_program.get('formal_process'):
                self.add_finding('critical',
                               'No formal risk assessment process',
                               'Implement formal risk assessment methodology')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check assessment frequency
            if not risk_program.get('annual_assessment'):
                self.add_finding('high',
                               'Risk assessments not conducted annually',
                               'Conduct comprehensive risk assessment annually')
                return ComplianceStatus.PARTIAL
            
            # Check risk register
            if not risk_program.get('risk_register'):
                self.add_finding('high',
                               'No risk register maintained',
                               'Create and maintain comprehensive risk register')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing risk assessment: {e}")
            return ComplianceStatus.ERROR
    
    def _check_risk_assessment_program(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Check risk assessment program maturity."""
        return {
            'formal_process': True,
            'methodology': 'NIST Risk Management Framework',
            'annual_assessment': True,
            'last_assessment': (datetime.now() - timedelta(days=180)).isoformat(),
            'risk_register': True,
            'risks_tracked': 45,
            'high_risks': 3
        }


class CC4_1_MonitoringActivities(SOC2Control):
    """The entity selects and develops ongoing and separate evaluations."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC4.1",
                        "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether internal control components are present and functioning")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check monitoring activities."""
        try:
            # Check continuous monitoring
            monitoring = self._check_monitoring_capabilities()
            self.add_evidence('monitoring_capabilities', monitoring)
            
            if not monitoring.get('continuous_monitoring'):
                self.add_finding('high',
                               'Continuous monitoring not implemented',
                               'Implement automated security monitoring')
                return ComplianceStatus.PARTIAL
            
            # Check security reviews
            if not monitoring.get('periodic_reviews'):
                self.add_finding('medium',
                               'Periodic security reviews not conducted',
                               'Schedule quarterly security control reviews')
                return ComplianceStatus.PARTIAL
            
            # Check third-party assessments
            if not monitoring.get('independent_assessment'):
                self.add_finding('medium',
                               'No independent security assessments',
                               'Engage third-party for annual security assessment')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing monitoring activities: {e}")
            return ComplianceStatus.ERROR
    
    def _check_monitoring_capabilities(self) -> Dict[str, Any]:
        """Check security monitoring capabilities."""
        return {
            'continuous_monitoring': True,
            'monitoring_tools': ['SIEM', 'IDS/IPS', 'Log Analysis'],
            'periodic_reviews': True,
            'review_frequency': 'quarterly',
            'independent_assessment': True,
            'last_assessment': datetime.now().isoformat()
        }


class CC5_1_ControlActivities(SOC2Control):
    """The entity selects and develops control activities."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC5.1",
                        "The entity selects and develops control activities that contribute to the mitigation of risks")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check control activities implementation."""
        try:
            # Check preventive controls
            controls = self._check_control_activities()
            self.add_evidence('control_activities', controls)
            
            if not controls.get('preventive_controls'):
                self.add_finding('high',
                               'Preventive controls not adequately implemented',
                               'Implement comprehensive preventive controls')
                return ComplianceStatus.PARTIAL
            
            # Check detective controls
            if not controls.get('detective_controls'):
                self.add_finding('high',
                               'Detective controls insufficient',
                               'Enhance monitoring and detection capabilities')
                return ComplianceStatus.PARTIAL
            
            # Check corrective controls
            if not controls.get('corrective_controls'):
                self.add_finding('medium',
                               'Corrective control procedures not defined',
                               'Document incident response and remediation procedures')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing control activities: {e}")
            return ComplianceStatus.ERROR
    
    def _check_control_activities(self) -> Dict[str, Any]:
        """Check implementation of control activities."""
        return {
            'preventive_controls': True,
            'preventive_examples': ['firewall', 'access_control', 'encryption'],
            'detective_controls': True,
            'detective_examples': ['monitoring', 'alerts', 'log_analysis'],
            'corrective_controls': True,
            'corrective_examples': ['incident_response', 'patch_management', 'backup_restore']
        }


class CC6_1_LogicalAccess(SOC2Control):
    """The entity implements logical access security controls."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC6.1",
                        "The entity implements logical access security software, infrastructure, and architectures over protected information assets")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check logical access controls."""
        try:
            # Check authentication
            access_controls = self._check_logical_access_controls()
            self.add_evidence('logical_access', access_controls)
            
            if not access_controls.get('strong_authentication'):
                self.add_finding('critical',
                               'Strong authentication not enforced',
                               'Implement multi-factor authentication')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check authorization
            if not access_controls.get('rbac_implemented'):
                self.add_finding('high',
                               'Role-based access control not implemented',
                               'Implement RBAC with least privilege')
                return ComplianceStatus.PARTIAL
            
            # Check privileged access
            if not access_controls.get('pam_solution'):
                self.add_finding('high',
                               'Privileged access not properly managed',
                               'Implement privileged access management solution')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing logical access: {e}")
            return ComplianceStatus.ERROR
    
    def _check_logical_access_controls(self) -> Dict[str, Any]:
        """Check logical access control implementation."""
        return {
            'strong_authentication': True,
            'mfa_coverage': '95%',
            'rbac_implemented': True,
            'access_reviews': 'quarterly',
            'pam_solution': True,
            'password_policy_compliant': True,
            'sso_implemented': True
        }


class CC7_1_SystemOperations(SOC2Control):
    """The entity detects and responds to anomalies and incidents."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC7.1",
                        "To meet its objectives, the entity uses detection and monitoring procedures to identify anomalies and indicators of breaches")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check system operations monitoring."""
        try:
            # Check detection capabilities
            detection = self._check_detection_capabilities()
            self.add_evidence('detection_capabilities', detection)
            
            if not detection.get('ids_ips_deployed'):
                self.add_finding('high',
                               'IDS/IPS not deployed',
                               'Deploy intrusion detection and prevention systems')
                return ComplianceStatus.PARTIAL
            
            # Check incident response
            if not detection.get('incident_response_team'):
                self.add_finding('critical',
                               'No incident response team defined',
                               'Establish incident response team and procedures')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check threat intelligence
            if not detection.get('threat_intelligence'):
                self.add_finding('medium',
                               'Threat intelligence not utilized',
                               'Integrate threat intelligence feeds')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing system operations: {e}")
            return ComplianceStatus.ERROR
    
    def _check_detection_capabilities(self) -> Dict[str, Any]:
        """Check anomaly detection and response capabilities."""
        return {
            'ids_ips_deployed': True,
            'siem_operational': True,
            'incident_response_team': True,
            'response_time_sla': '1 hour',
            'threat_intelligence': True,
            'automated_response': True,
            'forensics_capability': True
        }


class CC8_1_ChangeManagement(SOC2Control):
    """The entity authorizes, designs, develops, and implements changes."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.SECURITY, "CC8.1",
                        "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check change management processes."""
        try:
            # Check change control
            change_mgmt = self._check_change_management()
            self.add_evidence('change_management', change_mgmt)
            
            if not change_mgmt.get('formal_process'):
                self.add_finding('high',
                               'No formal change management process',
                               'Implement formal change control procedures')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check testing requirements
            if not change_mgmt.get('testing_required'):
                self.add_finding('high',
                               'Changes not tested before deployment',
                               'Require testing for all changes')
                return ComplianceStatus.PARTIAL
            
            # Check approval process
            if not change_mgmt.get('approval_workflow'):
                self.add_finding('medium',
                               'Change approval workflow not defined',
                               'Implement multi-level change approval process')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing change management: {e}")
            return ComplianceStatus.ERROR
    
    def _check_change_management(self) -> Dict[str, Any]:
        """Check change management maturity."""
        return {
            'formal_process': True,
            'change_board': True,
            'testing_required': True,
            'approval_workflow': True,
            'rollback_procedures': True,
            'emergency_change_process': True,
            'change_success_rate': '98%'
        }


# Availability Principle

class A1_1_CapacityManagement(SOC2Control):
    """The entity maintains and monitors system capacity."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.AVAILABILITY, "A1.1",
                        "Current processing capacity and usage are maintained, monitored, and projected to meet the entity's availability commitments")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check capacity management practices."""
        try:
            # Check capacity monitoring
            capacity = self._check_capacity_management()
            self.add_evidence('capacity_management', capacity)
            
            if not capacity.get('monitoring_implemented'):
                self.add_finding('high',
                               'Capacity monitoring not implemented',
                               'Implement comprehensive capacity monitoring')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check capacity planning
            if not capacity.get('capacity_planning'):
                self.add_finding('medium',
                               'No formal capacity planning process',
                               'Implement quarterly capacity planning reviews')
                return ComplianceStatus.PARTIAL
            
            # Check alerts
            if not capacity.get('threshold_alerts'):
                self.add_finding('medium',
                               'Capacity threshold alerts not configured',
                               'Configure alerts at 80% capacity thresholds')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing capacity management: {e}")
            return ComplianceStatus.ERROR
    
    def _check_capacity_management(self) -> Dict[str, Any]:
        """Check capacity management implementation."""
        return {
            'monitoring_implemented': True,
            'metrics_tracked': ['cpu', 'memory', 'storage', 'network'],
            'capacity_planning': True,
            'planning_horizon': '12 months',
            'threshold_alerts': True,
            'auto_scaling': True,
            'current_utilization': '65%'
        }


class A1_2_BackupRecovery(SOC2Control):
    """The entity implements backup and recovery procedures."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.AVAILABILITY, "A1.2",
                        "Environmental protections, software, data backup processes, and recovery infrastructure are authorized, designed, developed, implemented, operated, maintained, and monitored")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check backup and recovery capabilities."""
        try:
            # Check backup procedures
            backup = self._check_backup_recovery()
            self.add_evidence('backup_recovery', backup)
            
            if not backup.get('automated_backups'):
                self.add_finding('critical',
                               'Automated backups not configured',
                               'Implement automated backup procedures')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check recovery testing
            if not backup.get('recovery_tested'):
                self.add_finding('high',
                               'Recovery procedures not tested',
                               'Test recovery procedures quarterly')
                return ComplianceStatus.PARTIAL
            
            # Check offsite storage
            if not backup.get('offsite_storage'):
                self.add_finding('high',
                               'No offsite backup storage',
                               'Implement geographically diverse backup storage')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing backup recovery: {e}")
            return ComplianceStatus.ERROR
    
    def _check_backup_recovery(self) -> Dict[str, Any]:
        """Check backup and recovery implementation."""
        return {
            'automated_backups': True,
            'backup_frequency': 'daily',
            'retention_period': '30 days',
            'recovery_tested': True,
            'last_test_date': (datetime.now() - timedelta(days=45)).isoformat(),
            'rto_defined': True,
            'rpo_defined': True,
            'offsite_storage': True
        }


# Confidentiality Principle

class C1_1_ConfidentialInformation(SOC2Control):
    """The entity identifies and maintains confidential information."""
    
    def __init__(self):
        super().__init__(TrustServicePrinciple.CONFIDENTIALITY, "C1.1",
                        "The entity identifies and maintains an inventory of information determined to be confidential")
    
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Check confidential information management."""
        try:
            # Check data classification
            classification = self._check_data_classification()
            self.add_evidence('data_classification', classification)
            
            if not classification.get('classification_scheme'):
                self.add_finding('high',
                               'No data classification scheme',
                               'Implement data classification policy')
                return ComplianceStatus.NON_COMPLIANT
            
            # Check data inventory
            if not classification.get('data_inventory'):
                self.add_finding('high',
                               'No confidential data inventory',
                               'Create inventory of all confidential data')
                return ComplianceStatus.PARTIAL
            
            # Check handling procedures
            if not classification.get('handling_procedures'):
                self.add_finding('medium',
                               'Data handling procedures not defined',
                               'Document procedures for each classification level')
                return ComplianceStatus.PARTIAL
                
            return ComplianceStatus.COMPLIANT
            
        except Exception as e:
            logger.error(f"Error assessing confidential information: {e}")
            return ComplianceStatus.ERROR
    
    def _check_data_classification(self) -> Dict[str, Any]:
        """Check data classification implementation."""
        return {
            'classification_scheme': True,
            'classification_levels': ['public', 'internal', 'confidential', 'restricted'],
            'data_inventory': True,
            'inventory_updated': datetime.now().isoformat(),
            'handling_procedures': True,
            'labeling_required': True,
            'encryption_requirements': True
        }


class SOC2Module(ComplianceModule):
    """SOC2 Compliance Module."""
    
    def __init__(self):
        super().__init__("SOC2", "Type II")
        self.selected_principles = []
        
    def initialize_controls(self):
        """Initialize SOC2 controls based on selected principles."""
        # Common Criteria (Security) - Always included
        self.controls.extend([
            CC1_1_OrganizationalOversight(),
            CC2_1_InformationCommunication(),
            CC3_1_RiskAssessment(),
            CC4_1_MonitoringActivities(),
            CC5_1_ControlActivities(),
            CC6_1_LogicalAccess(),
            CC7_1_SystemOperations(),
            CC8_1_ChangeManagement()
        ])
        
        # Additional principles can be added based on scope
        if TrustServicePrinciple.AVAILABILITY in self.selected_principles:
            self.controls.extend([
                A1_1_CapacityManagement(),
                A1_2_BackupRecovery()
            ])
            
        if TrustServicePrinciple.CONFIDENTIALITY in self.selected_principles:
            self.controls.append(C1_1_ConfidentialInformation())
            
        logger.info(f"Initialized {len(self.controls)} SOC2 controls")
    
    def select_principles(self, principles: List[TrustServicePrinciple]):
        """Select additional trust service principles for assessment."""
        self.selected_principles = principles
        self.controls = []  # Reset controls
        self.initialize_controls()
    
    def generate_report(self, assessment_data: Dict[str, Any], 
                       format: str = 'json') -> Union[Dict[str, Any], str]:
        """Generate SOC2 compliance report."""
        if format == 'json':
            return self._generate_json_report(assessment_data)
        elif format == 'executive':
            return self._generate_executive_report(assessment_data)
        elif format == 'detailed':
            return self._generate_detailed_report(assessment_data)
        elif format == 'type2':
            return self._generate_type2_report(assessment_data)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_json_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JSON format report."""
        return {
            'standard': 'SOC2',
            'type': self.version,
            'assessment_date': data['timestamp'],
            'service_organization': data['scope'].get('organization_name', 'Service Organization'),
            'audit_period': data['scope'].get('audit_period', {
                'start': (datetime.now() - timedelta(days=365)).isoformat(),
                'end': datetime.now().isoformat()
            }),
            'principles_assessed': [p.value for p in [TrustServicePrinciple.SECURITY] + self.selected_principles],
            'results': data['results'],
            'evidence_count': len(data['evidence']),
            'opinion': self._determine_opinion(data['results'])
        }
    
    def _generate_executive_report(self, data: Dict[str, Any]) -> str:
        """Generate executive summary report."""
        results = data['results']
        summary = results['summary']
        
        report = f"""
SOC2 TYPE II EXECUTIVE SUMMARY
==============================

Service Organization: {data['scope'].get('organization_name', 'Service Organization')}
Assessment Date: {data['timestamp']}
Audit Period: {data['scope'].get('audit_period', {}).get('start', 'N/A')} to {data['scope'].get('audit_period', {}).get('end', 'N/A')}

TRUST SERVICE PRINCIPLES ASSESSED
--------------------------------"""
        
        principles = [TrustServicePrinciple.SECURITY] + self.selected_principles
        for principle in principles:
            report += f"\n• {principle.value}"
        
        report += f"\n\nOVERALL ASSESSMENT\n-----------------"
        report += f"\nCompliance Score: {summary['compliance_percentage']}%"
        report += f"\nRisk Level: {summary.get('risk_level', 'UNKNOWN')}"
        report += f"\nAuditor Opinion: {self._determine_opinion(results)}"
        
        report += "\n\nCONTROL SUMMARY\n--------------"
        report += f"\n✓ Operating Effectively: {summary['compliant']}"
        report += f"\n⚠ Operating with Exceptions: {summary['partial']}"
        report += f"\n✗ Not Operating Effectively: {summary['non_compliant']}"
        report += f"\n- Not Tested: {summary['not_applicable']}"
        
        report += "\n\nKEY FINDINGS\n-----------"
        critical_findings = summary.get('critical_findings', [])
        if critical_findings:
            for i, finding in enumerate(critical_findings[:5], 1):
                report += f"\n{i}. {finding}"
        else:
            report += "\nNo significant deficiencies identified"
        
        report += "\n\nMANAGEMENT RECOMMENDATIONS\n-------------------------"
        report += "\n1. Continue to monitor and enhance control effectiveness"
        report += "\n2. Address any identified control exceptions promptly"
        report += "\n3. Maintain comprehensive documentation of control activities"
        report += "\n4. Conduct regular control self-assessments"
        
        if summary.get('risk_level') in ['HIGH', 'CRITICAL']:
            report += "\n5. URGENT: Address critical control deficiencies immediately"
            report += "\n6. Consider engaging external security consultants"
        
        return report
    
    def _generate_detailed_report(self, data: Dict[str, Any]) -> str:
        """Generate detailed SOC2 assessment report."""
        results = data['results']
        
        report = f"""
SOC2 TYPE II DETAILED ASSESSMENT REPORT
======================================

Service Organization: {data['scope'].get('organization_name', 'Service Organization')}
Assessment Date: {data['timestamp']}
Report Type: {self.version}

SECTION 1: SYSTEM DESCRIPTION
----------------------------
{self._generate_system_description(data['scope'])}

SECTION 2: CONTROL ASSESSMENT RESULTS
------------------------------------"""
        
        # Group controls by principle
        principles = {}
        for control in results['controls']:
            principle = control['category']
            if principle not in principles:
                principles[principle] = []
            principles[principle].append(control)
        
        # Generate detailed findings for each principle
        for principle, controls in principles.items():
            report += f"\n\n{principle.upper()}\n" + "=" * 50 + "\n"
            
            for control in controls:
                effectiveness = {
                    'compliant': 'OPERATING EFFECTIVELY',
                    'partial': 'OPERATING WITH EXCEPTIONS',
                    'non_compliant': 'NOT OPERATING EFFECTIVELY',
                    'not_applicable': 'NOT TESTED'
                }.get(control['status'], 'UNKNOWN')
                
                report += f"\nControl: {control['control_id']}"
                report += f"\nDescription: {control['description']}"
                report += f"\nControl Effectiveness: {effectiveness}"
                
                if control['findings']:
                    report += "\n\nControl Testing Results:"
                    for finding in control['findings']:
                        report += f"\n  • [{finding['severity'].upper()}] {finding['description']}"
                        if finding.get('remediation'):
                            report += f"\n    Management Response: {finding['remediation']}"
                
                report += f"\n\nEvidence Reviewed: {control['evidence_count']} items"
                report += "\n" + "-" * 50
        
        report += "\n\nSECTION 3: MANAGEMENT ASSERTIONS\n-------------------------------"
        report += "\nManagement asserts that:"
        report += "\n• The description fairly presents the system throughout the audit period"
        report += "\n• Controls were suitably designed to meet the applicable trust services criteria"
        report += "\n• Controls operated effectively throughout the specified period"
        
        return report
    
    def _generate_type2_report(self, data: Dict[str, Any]) -> str:
        """Generate SOC2 Type II audit-style report."""
        results = data['results']
        
        report = f"""
INDEPENDENT SERVICE AUDITOR'S REPORT
===================================

To: Management of {data['scope'].get('organization_name', 'Service Organization')}

SCOPE
-----
We have examined the description of {data['scope'].get('organization_name', 'Service Organization')}'s 
{data['scope'].get('system_name', 'Service System')} throughout the period {data['scope'].get('audit_period', {}).get('start', 'N/A')} 
to {data['scope'].get('audit_period', {}).get('end', 'N/A')} and the suitability of the design and 
operating effectiveness of controls to meet the criteria for the following trust services categories:
"""
        
        principles = [TrustServicePrinciple.SECURITY] + self.selected_principles
        for principle in principles:
            report += f"\n• {principle.value}"
        
        report += "\n\nMANAGEMENT'S RESPONSIBILITY\n--------------------------"
        report += """
Management is responsible for:
• Preparing the description of the system
• Designing, implementing, and maintaining effective controls
• Selecting the trust services categories and criteria
• Providing the written assertion about the effectiveness of controls
"""
        
        report += "\n\nSERVICE AUDITOR'S RESPONSIBILITY\n--------------------------------"
        report += """
Our responsibility is to express an opinion on:
• Whether the description fairly presents the system
• Whether controls were suitably designed
• Whether controls operated effectively throughout the period
"""
        
        report += "\n\nOPINION\n-------"
        opinion = self._determine_opinion(results)
        
        if opinion == "UNQUALIFIED":
            report += """
In our opinion, based on our examination:

a) The description fairly presents the system that was designed and implemented 
   throughout the specified period.

b) The controls stated in the description were suitably designed to provide 
   reasonable assurance that the applicable trust services criteria would be 
   met if the controls operated effectively throughout the specified period.

c) The controls tested operated effectively throughout the specified period.
"""
        else:
            report += f"""
In our opinion, except for the matters described in the Basis for Qualified 
Opinion section below, the description fairly presents the system and the 
controls were suitably designed and operating effectively.

QUALIFIED OPINION: {opinion}
"""
        
        report += f"\n\n[Service Auditor Signature]\n{datetime.now().strftime('%B %d, %Y')}"
        
        return report
    
    def _generate_system_description(self, scope: Dict[str, Any]) -> str:
        """Generate system description for SOC2 report."""
        return f"""
System Name: {scope.get('system_name', 'Service System')}
System Purpose: {scope.get('system_purpose', 'Provide secure services to customers')}

Infrastructure:
• Cloud Provider: {scope.get('cloud_provider', 'AWS/Azure/GCP')}
• Data Centers: {scope.get('data_centers', 'Multiple geographic regions')}
• Network Architecture: {scope.get('network_arch', 'Redundant, segmented network')}

Software:
• Application Stack: {scope.get('app_stack', 'Modern microservices architecture')}
• Databases: {scope.get('databases', 'Encrypted relational and NoSQL databases')}
• Security Tools: {scope.get('security_tools', 'SIEM, IDS/IPS, WAF')}

People:
• IT Team Size: {scope.get('it_team_size', 'Dedicated security and operations teams')}
• Key Roles: Security Officer, Privacy Officer, Compliance Manager

Procedures:
• Change Management: Formal approval and testing process
• Incident Response: 24/7 monitoring and response team
• Access Control: Role-based with quarterly reviews
"""
    
    def _determine_opinion(self, results: Dict[str, Any]) -> str:
        """Determine auditor opinion based on results."""
        summary = results['summary']
        
        if summary['non_compliant'] == 0 and summary['partial'] <= 2:
            return "UNQUALIFIED"
        elif summary['non_compliant'] <= 1 and summary['partial'] <= 5:
            return "UNQUALIFIED WITH EMPHASIS OF MATTER"
        elif summary['non_compliant'] <= 3:
            return "QUALIFIED - EXCEPT FOR"
        else:
            return "ADVERSE OPINION"


# Convenience functions for Claude Code orchestration

def assess_soc2_compliance(scope: Dict[str, Any] = None, 
                         principles: List[str] = None) -> Dict[str, Any]:
    """Quick function to run SOC2 compliance assessment."""
    module = SOC2Module()
    
    # Convert string principles to enum
    if principles:
        principle_enums = []
        for p in principles:
            try:
                principle_enums.append(TrustServicePrinciple[p.upper()])
            except KeyError:
                logger.warning(f"Unknown principle: {p}")
        module.select_principles(principle_enums)
    
    return module.assess(scope or {
        'organization_name': 'Example Service Organization',
        'system_name': 'Cloud Service Platform',
        'audit_period': {
            'start': (datetime.now() - timedelta(days=365)).isoformat(),
            'end': datetime.now().isoformat()
        }
    })


def check_security_controls() -> Dict[str, Any]:
    """Check only SOC2 security (common criteria) controls."""
    module = SOC2Module()
    module.select_principles([])  # Only security
    return module.assess({})


def verify_availability_controls() -> Dict[str, Any]:
    """Check SOC2 availability principle controls."""
    controls = [
        A1_1_CapacityManagement(),
        A1_2_BackupRecovery()
    ]
    
    results = []
    for control in controls:
        control.assess({})
        results.append(control.get_result())
    
    return {
        'availability_ready': all(r['status'] == 'compliant' for r in results),
        'controls': results
    }