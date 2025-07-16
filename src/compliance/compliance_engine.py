"""
SuperSleuth Network Compliance Engine

This module provides the core compliance assessment framework that Claude Code can orchestrate
to perform compliance checks against PCI DSS, HIPAA, SOC2, and other standards.
"""

import json
import datetime
from typing import Dict, List, Optional, Any, Union
from abc import ABC, abstractmethod
import hashlib
from enum import Enum

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ComplianceStatus(Enum):
    """Compliance check status values."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non-compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    NOT_ASSESSED = "not_assessed"


class ComplianceControl(ABC):
    """Abstract base class for compliance controls."""
    
    def __init__(self, control_id: str, description: str, category: str):
        self.control_id = control_id
        self.description = description
        self.category = category
        self.evidence = []
        self.status = ComplianceStatus.NOT_ASSESSED
        self.findings = []
        
    @abstractmethod
    def assess(self, scope: Dict[str, Any]) -> ComplianceStatus:
        """Perform the compliance assessment for this control."""
        pass
        
    def add_evidence(self, evidence_type: str, data: Any, description: str = ""):
        """Add evidence for this control assessment."""
        self.evidence.append({
            'timestamp': datetime.datetime.now().isoformat(),
            'type': evidence_type,
            'data': data,
            'description': description,
            'hash': self._hash_evidence(data)
        })
        
    def add_finding(self, severity: str, description: str, remediation: str = ""):
        """Add a finding for this control."""
        self.findings.append({
            'severity': severity,
            'description': description,
            'remediation': remediation,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    def _hash_evidence(self, data: Any) -> str:
        """Generate hash for evidence integrity."""
        data_str = json.dumps(data, sort_keys=True) if isinstance(data, (dict, list)) else str(data)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]
        
    def get_result(self) -> Dict[str, Any]:
        """Get the assessment result for this control."""
        return {
            'control_id': self.control_id,
            'description': self.description,
            'category': self.category,
            'status': self.status.value,
            'findings': self.findings,
            'evidence_count': len(self.evidence),
            'assessed_at': datetime.datetime.now().isoformat()
        }


class ComplianceModule(ABC):
    """Abstract base class for compliance standard modules."""
    
    def __init__(self, standard_name: str, version: str):
        self.standard_name = standard_name
        self.version = version
        self.controls = []
        self.metadata = {
            'created_at': datetime.datetime.now().isoformat(),
            'module_version': '1.0.0'
        }
        
    @abstractmethod
    def initialize_controls(self):
        """Initialize all controls for this compliance standard."""
        pass
        
    def assess(self, scope: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run compliance assessment for all controls."""
        if not self.controls:
            self.initialize_controls()
            
        results = {
            'standard': self.standard_name,
            'version': self.version,
            'assessment_time': datetime.datetime.now().isoformat(),
            'scope': scope or {},
            'controls': [],
            'summary': {
                'total_controls': len(self.controls),
                'compliant': 0,
                'non_compliant': 0,
                'partial': 0,
                'not_applicable': 0,
                'errors': 0
            }
        }
        
        for control in self.controls:
            try:
                # Skip if control is not applicable to scope
                if scope and not self._is_control_applicable(control, scope):
                    control.status = ComplianceStatus.NOT_APPLICABLE
                else:
                    control.status = control.assess(scope or {})
                    
                # Update summary
                status_key = control.status.value.replace('_', '_')
                if status_key in results['summary']:
                    results['summary'][status_key] += 1
                    
                results['controls'].append(control.get_result())
                
            except Exception as e:
                logger.error(f"Error assessing control {control.control_id}: {e}")
                control.status = ComplianceStatus.ERROR
                control.add_finding('error', f'Assessment error: {str(e)}')
                results['summary']['errors'] += 1
                results['controls'].append(control.get_result())
                
        # Calculate compliance percentage
        total_assessed = results['summary']['compliant'] + results['summary']['non_compliant'] + results['summary']['partial']
        if total_assessed > 0:
            results['summary']['compliance_percentage'] = round(
                (results['summary']['compliant'] / total_assessed) * 100, 2
            )
        else:
            results['summary']['compliance_percentage'] = 0
            
        return results
        
    def _is_control_applicable(self, control: ComplianceControl, scope: Dict[str, Any]) -> bool:
        """Determine if a control is applicable based on scope."""
        # Override in subclasses for specific applicability logic
        return True
        
    def get_collected_evidence(self) -> List[Dict[str, Any]]:
        """Get all collected evidence from controls."""
        all_evidence = []
        for control in self.controls:
            for evidence in control.evidence:
                all_evidence.append({
                    'control_id': control.control_id,
                    'evidence': evidence
                })
        return all_evidence
        
    def get_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of assessment results."""
        summary = results['summary'].copy()
        
        # Add risk analysis
        risk_score = self._calculate_risk_score(results)
        summary['risk_score'] = risk_score
        summary['risk_level'] = self._get_risk_level(risk_score)
        
        # Add key findings
        summary['critical_findings'] = self._get_critical_findings(results)
        summary['quick_wins'] = self._get_quick_wins(results)
        
        return summary
        
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-100)."""
        # Simple risk calculation - can be overridden for complex logic
        non_compliant = results['summary']['non_compliant']
        partial = results['summary']['partial']
        total = results['summary']['total_controls']
        
        if total == 0:
            return 0
            
        risk_score = ((non_compliant * 1.0 + partial * 0.5) / total) * 100
        return round(risk_score, 2)
        
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 70:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "MINIMAL"
            
    def _get_critical_findings(self, results: Dict[str, Any]) -> List[str]:
        """Extract critical findings from results."""
        critical = []
        for control in results['controls']:
            if control['status'] == 'non_compliant':
                for finding in control['findings']:
                    if finding['severity'] in ['critical', 'high']:
                        critical.append(f"{control['control_id']}: {finding['description']}")
        return critical[:5]  # Top 5 critical findings
        
    def _get_quick_wins(self, results: Dict[str, Any]) -> List[str]:
        """Identify quick win remediation items."""
        quick_wins = []
        for control in results['controls']:
            if control['status'] in ['non_compliant', 'partial']:
                for finding in control['findings']:
                    if finding.get('remediation') and 'quick' in finding['remediation'].lower():
                        quick_wins.append(f"{control['control_id']}: {finding['remediation']}")
        return quick_wins[:3]  # Top 3 quick wins
        
    @abstractmethod
    def generate_report(self, assessment_data: Dict[str, Any], 
                       format: str = 'json') -> Union[Dict[str, Any], str, bytes]:
        """Generate compliance report in specified format."""
        pass


class ComplianceEngine:
    """Main compliance assessment engine for Claude Code orchestration."""
    
    def __init__(self):
        self.compliance_modules = {}
        self.evidence_store = {}
        self.assessment_history = []
        
    def register_module(self, standard_name: str, module_instance: ComplianceModule):
        """Register a compliance module with the engine."""
        self.compliance_modules[standard_name] = module_instance
        logger.info(f"Registered compliance module: {standard_name}")
        
    def list_standards(self) -> List[Dict[str, str]]:
        """List all registered compliance standards."""
        return [
            {
                'name': name,
                'version': module.version,
                'controls_count': len(module.controls) if module.controls else 'Not initialized'
            }
            for name, module in self.compliance_modules.items()
        ]
        
    def run_assessment(self, standard_name: str, scope: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run compliance assessment for a specific standard."""
        if standard_name not in self.compliance_modules:
            raise ValueError(f"Compliance standard {standard_name} not registered")
            
        logger.info(f"Starting {standard_name} compliance assessment")
        
        module = self.compliance_modules[standard_name]
        results = module.assess(scope)
        
        # Store evidence
        assessment_id = f"{standard_name}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.evidence_store[assessment_id] = {
            'standard': standard_name,
            'timestamp': datetime.datetime.now().isoformat(),
            'scope': scope,
            'results': results,
            'evidence': module.get_collected_evidence()
        }
        
        # Add to history
        self.assessment_history.append({
            'assessment_id': assessment_id,
            'standard': standard_name,
            'timestamp': datetime.datetime.now().isoformat(),
            'compliance_percentage': results['summary']['compliance_percentage']
        })
        
        logger.info(f"Completed {standard_name} assessment: {assessment_id}")
        
        return {
            'assessment_id': assessment_id,
            'results': results,
            'summary': module.get_summary(results)
        }
        
    def run_multi_standard_assessment(self, standards: List[str], 
                                    scope: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run assessment against multiple standards simultaneously."""
        results = {
            'assessment_time': datetime.datetime.now().isoformat(),
            'scope': scope,
            'standards': {}
        }
        
        for standard in standards:
            if standard in self.compliance_modules:
                assessment = self.run_assessment(standard, scope)
                results['standards'][standard] = assessment
            else:
                logger.warning(f"Standard {standard} not registered, skipping")
                
        return results
        
    def generate_report(self, assessment_id: str, format: str = 'json') -> Union[Dict[str, Any], str, bytes]:
        """Generate report for a completed assessment."""
        if assessment_id not in self.evidence_store:
            raise ValueError(f"Assessment ID {assessment_id} not found")
            
        assessment = self.evidence_store[assessment_id]
        standard_name = assessment['standard']
        module = self.compliance_modules[standard_name]
        
        return module.generate_report(assessment, format)
        
    def get_assessment_history(self, standard_name: str = None, 
                             limit: int = 10) -> List[Dict[str, Any]]:
        """Get assessment history, optionally filtered by standard."""
        history = self.assessment_history
        
        if standard_name:
            history = [h for h in history if h['standard'] == standard_name]
            
        return sorted(history, key=lambda x: x['timestamp'], reverse=True)[:limit]
        
    def compare_assessments(self, assessment_id1: str, assessment_id2: str) -> Dict[str, Any]:
        """Compare two assessments to show changes."""
        if assessment_id1 not in self.evidence_store or assessment_id2 not in self.evidence_store:
            raise ValueError("One or both assessment IDs not found")
            
        assess1 = self.evidence_store[assessment_id1]
        assess2 = self.evidence_store[assessment_id2]
        
        if assess1['standard'] != assess2['standard']:
            raise ValueError("Cannot compare assessments from different standards")
            
        # Extract control statuses
        controls1 = {c['control_id']: c['status'] for c in assess1['results']['controls']}
        controls2 = {c['control_id']: c['status'] for c in assess2['results']['controls']}
        
        comparison = {
            'standard': assess1['standard'],
            'assessment1': {
                'id': assessment_id1,
                'timestamp': assess1['timestamp'],
                'compliance_percentage': assess1['results']['summary']['compliance_percentage']
            },
            'assessment2': {
                'id': assessment_id2,
                'timestamp': assess2['timestamp'],
                'compliance_percentage': assess2['results']['summary']['compliance_percentage']
            },
            'changes': {
                'improved': [],
                'degraded': [],
                'unchanged': []
            }
        }
        
        # Compare controls
        for control_id in controls1:
            if control_id in controls2:
                status1 = controls1[control_id]
                status2 = controls2[control_id]
                
                if status1 != status2:
                    if self._is_improvement(status1, status2):
                        comparison['changes']['improved'].append({
                            'control_id': control_id,
                            'from': status1,
                            'to': status2
                        })
                    else:
                        comparison['changes']['degraded'].append({
                            'control_id': control_id,
                            'from': status1,
                            'to': status2
                        })
                else:
                    comparison['changes']['unchanged'].append(control_id)
                    
        return comparison
        
    def _is_improvement(self, status1: str, status2: str) -> bool:
        """Determine if status change is an improvement."""
        status_order = {
            'non_compliant': 0,
            'partial': 1,
            'compliant': 2,
            'not_applicable': 3
        }
        
        score1 = status_order.get(status1, -1)
        score2 = status_order.get(status2, -1)
        
        return score2 > score1


# Convenience functions for Claude Code orchestration

def create_compliance_engine() -> ComplianceEngine:
    """Create and initialize a compliance engine instance."""
    engine = ComplianceEngine()
    
    # Register available compliance modules
    try:
        from .pci_dss import PCIDSSModule
        engine.register_module('PCI_DSS', PCIDSSModule())
    except ImportError:
        logger.warning("PCI DSS module not available")
        
    try:
        from .hipaa import HIPAAModule
        engine.register_module('HIPAA', HIPAAModule())
    except ImportError:
        logger.warning("HIPAA module not available")
        
    try:
        from .soc2 import SOC2Module
        engine.register_module('SOC2', SOC2Module())
    except ImportError:
        logger.warning("SOC2 module not available")
        
    return engine


def quick_compliance_check(standard: str, scope: Dict[str, Any] = None) -> Dict[str, Any]:
    """Perform a quick compliance check for a specific standard."""
    engine = create_compliance_engine()
    return engine.run_assessment(standard, scope)


def generate_compliance_report(assessment_id: str, format: str = 'json') -> Union[Dict[str, Any], str]:
    """Generate a compliance report from a completed assessment."""
    engine = create_compliance_engine()
    return engine.generate_report(assessment_id, format)