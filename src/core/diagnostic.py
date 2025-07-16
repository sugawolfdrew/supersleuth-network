"""
Core diagnostic framework for SuperSleuth Network
"""

import logging
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod
import uuid

from ..utils.logger import get_logger
from .event_logger import event_logger, EventType, EventSeverity


class DiagnosticResult:
    """Container for diagnostic results"""
    
    def __init__(self, test_name: str, status: str = "pending"):
        self.test_name = test_name
        self.status = status  # pending, running, completed, failed
        self.start_time = datetime.now()
        self.end_time = None
        self.results = {}
        self.errors = []
        self.warnings = []
        self.recommendations = []
        
    def complete(self, results: Dict[str, Any]):
        """Mark test as complete with results"""
        self.status = "completed"
        self.end_time = datetime.now()
        self.results = results
        
    def fail(self, error: str):
        """Mark test as failed"""
        self.status = "failed"
        self.end_time = datetime.now()
        self.errors.append(error)
        
    def add_warning(self, warning: str):
        """Add a warning to the results"""
        self.warnings.append(warning)
        
    def add_recommendation(self, recommendation: str):
        """Add a recommendation based on findings"""
        self.recommendations.append(recommendation)
        
    def to_dict(self) -> Dict:
        """Convert result to dictionary"""
        return {
            'test_name': self.test_name,
            'status': self.status,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': str(self.end_time - self.start_time) if self.end_time else None,
            'results': self.results,
            'errors': self.errors,
            'warnings': self.warnings,
            'recommendations': self.recommendations
        }


class BaseDiagnostic(ABC):
    """Abstract base class for all diagnostic modules"""
    
    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or get_logger(self.__class__.__name__)
        self.session_id = str(uuid.uuid4())
        self.results = []
        
    def run(self) -> DiagnosticResult:
        """Execute the diagnostic test"""
        result = DiagnosticResult(self.__class__.__name__)
        
        # Log diagnostic start
        event_logger.log_event(
            EventType.DIAGNOSTIC_START,
            EventSeverity.INFO,
            self.__class__.__name__,
            f"Starting {self.__class__.__name__} diagnostic",
            {"session_id": self.session_id}
        )
        
        try:
            # Call the actual implementation
            self._run_diagnostic(result)
            
            # Log completion
            event_logger.log_event(
                EventType.DIAGNOSTIC_COMPLETE,
                EventSeverity.INFO,
                self.__class__.__name__,
                f"Completed {self.__class__.__name__} diagnostic",
                {
                    "session_id": self.session_id,
                    "duration": str(result.end_time - result.start_time) if result.end_time else None,
                    "status": result.status
                }
            )
            
        except Exception as e:
            # Log error
            event_logger.log_event(
                EventType.DIAGNOSTIC_ERROR,
                EventSeverity.ERROR,
                self.__class__.__name__,
                f"Error in {self.__class__.__name__}: {str(e)}",
                {"session_id": self.session_id, "error": str(e)}
            )
            result.fail(str(e))
            
        return result
    
    @abstractmethod
    def _run_diagnostic(self, result: DiagnosticResult):
        """Actual diagnostic implementation - to be overridden"""
        pass
        
    @abstractmethod
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met for this diagnostic"""
        pass
        
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements for this diagnostic"""
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'metadata_only',
            'risk_level': 'low'
        }


class DiagnosticSuite:
    """Orchestrates multiple diagnostic tests"""
    
    def __init__(self, client_config: Dict, audit_logger: logging.Logger):
        self.client_config = self._validate_client_config(client_config)
        self.audit_logger = audit_logger
        self.session_id = self._generate_session_id()
        self.diagnostics: List[BaseDiagnostic] = []
        self.results: List[DiagnosticResult] = []
        
    def _validate_client_config(self, config: Dict) -> Dict:
        """Validate client configuration meets enterprise standards"""
        required_fields = [
            'client_name', 'sow_reference', 'authorized_subnets',
            'compliance_requirements', 'escalation_contacts'
        ]
        
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required client config: {field}")
        
        return config
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier for audit trail"""
        timestamp = datetime.now().isoformat()
        client_hash = hashlib.md5(
            self.client_config['client_name'].encode()
        ).hexdigest()[:8]
        return f"SN-{client_hash}-{timestamp.replace(':', '').replace('-', '')[:12]}"
    
    def add_diagnostic(self, diagnostic: BaseDiagnostic):
        """Add a diagnostic to the suite"""
        self.diagnostics.append(diagnostic)
        
    def execute(self) -> Dict[str, Any]:
        """Execute all diagnostics in the suite"""
        self.audit_logger.info(
            f"Starting diagnostic session {self.session_id} "
            f"for client {self.client_config['client_name']}"
        )
        
        try:
            # Pre-flight authorization check
            if not self._verify_authorization():
                return self._abort_with_audit("Insufficient authorization")
            
            # Execute each diagnostic
            for diagnostic in self.diagnostics:
                self.audit_logger.info(
                    f"Executing diagnostic: {diagnostic.__class__.__name__}"
                )
                
                # Check prerequisites
                if not diagnostic.validate_prerequisites():
                    self.audit_logger.warning(
                        f"Prerequisites not met for {diagnostic.__class__.__name__}"
                    )
                    continue
                
                # Run diagnostic
                try:
                    result = diagnostic.run()
                    self.results.append(result)
                    self.audit_logger.info(
                        f"Diagnostic {diagnostic.__class__.__name__} completed "
                        f"with status: {result.status}"
                    )
                    
                    # Log findings if any
                    if result.warnings:
                        for warning in result.warnings:
                            event_logger.log_event(
                                EventType.ALERT,
                                EventSeverity.WARNING,
                                diagnostic.__class__.__name__,
                                warning,
                                {"session_id": self.session_id}
                            )
                except Exception as e:
                    self.audit_logger.error(
                        f"Diagnostic {diagnostic.__class__.__name__} failed: {str(e)}"
                    )
                    failed_result = DiagnosticResult(diagnostic.__class__.__name__)
                    failed_result.fail(str(e))
                    self.results.append(failed_result)
            
            # Generate summary report
            summary = self._generate_summary()
            
            self.audit_logger.info(
                f"Diagnostic session {self.session_id} completed successfully"
            )
            
            return summary
            
        except Exception as e:
            self.audit_logger.error(
                f"Diagnostic session {self.session_id} failed: {str(e)}"
            )
            return self._emergency_abort(str(e))
    
    def _verify_authorization(self) -> bool:
        """Verify authorization for all diagnostics"""
        # In production, this would check against actual authorization system
        return True
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate executive summary of all diagnostic results"""
        return {
            'session_id': self.session_id,
            'client': self.client_config['client_name'],
            'timestamp': datetime.now().isoformat(),
            'total_diagnostics': len(self.diagnostics),
            'completed': len([r for r in self.results if r.status == 'completed']),
            'failed': len([r for r in self.results if r.status == 'failed']),
            'results': [r.to_dict() for r in self.results],
            'overall_health_score': self._calculate_health_score(),
            'critical_findings': self._extract_critical_findings(),
            'recommendations': self._consolidate_recommendations()
        }
    
    def _calculate_health_score(self) -> int:
        """Calculate overall network health score"""
        if not self.results:
            return 0
            
        completed = [r for r in self.results if r.status == 'completed']
        if not completed:
            return 0
            
        # Simple scoring algorithm - can be made more sophisticated
        total_score = 0
        for result in completed:
            if not result.errors:
                total_score += 100
            elif result.warnings:
                total_score += 70
            else:
                total_score += 40
                
        return int(total_score / len(completed))
    
    def _extract_critical_findings(self) -> List[Dict]:
        """Extract critical findings that need immediate attention"""
        critical = []
        for result in self.results:
            if result.errors:
                critical.append({
                    'diagnostic': result.test_name,
                    'errors': result.errors,
                    'impact': 'high'
                })
        return critical
    
    def _consolidate_recommendations(self) -> List[str]:
        """Consolidate all recommendations from diagnostics"""
        recommendations = []
        for result in self.results:
            recommendations.extend(result.recommendations)
        # Remove duplicates while preserving order
        return list(dict.fromkeys(recommendations))
    
    def _abort_with_audit(self, reason: str) -> Dict:
        """Abort session with full audit trail"""
        self.audit_logger.error(f"Session aborted: {reason}")
        return {
            'session_id': self.session_id,
            'status': 'aborted',
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
    
    def _emergency_abort(self, error: str) -> Dict:
        """Emergency abort with error details"""
        self.audit_logger.critical(f"Emergency abort: {error}")
        return {
            'session_id': self.session_id,
            'status': 'emergency_abort',
            'error': error,
            'timestamp': datetime.now().isoformat(),
            'escalation_required': True,
            'contacts': self.client_config.get('escalation_contacts', [])
        }


class AdaptiveDiagnosticBrain:
    """AI that adjusts diagnostic strategy based on findings"""
    
    def __init__(self):
        self.findings_so_far = []
        self.current_hypothesis = None
        self.diagnostic_confidence = 0.0
        self.diagnostic_history = []
        self.logger = get_logger("AdaptiveBrain")
        
    def process_new_data(self, data_point: Dict[str, Any]):
        """Continuously refine diagnostic approach as new data arrives"""
        
        self.findings_so_far.append(data_point)
        self.diagnostic_history.append({
            'timestamp': datetime.now().isoformat(),
            'data': data_point,
            'hypothesis': self.current_hypothesis,
            'confidence': self.diagnostic_confidence
        })
        
        # Log adaptive processing
        event_logger.log_event(
            EventType.SYSTEM,
            EventSeverity.DEBUG,
            "AdaptiveBrain",
            f"Processing new data point: {data_point.get('type', 'unknown')}",
            data_point
        )
        
        # Generate new hypothesis based on all findings
        new_hypothesis = self.generate_hypothesis(self.findings_so_far)
        
        if new_hypothesis != self.current_hypothesis:
            self.logger.info(f"""
🧠 SUPERSLEUTH DIAGNOSTIC UPDATE:
Previous hypothesis: {self.current_hypothesis}
New hypothesis: {new_hypothesis}
Confidence level: {self.calculate_confidence()}%

🔄 ADJUSTING DIAGNOSTIC APPROACH:
{self.explain_strategy_change()}

🛠️ GENERATING NEW TOOLS:
{self.create_additional_diagnostic_tools()}
            """)
            
            self.current_hypothesis = new_hypothesis
            return self.build_next_diagnostic_step()
    
    def generate_hypothesis(self, findings: List[Dict]) -> str:
        """Generate hypothesis based on current findings"""
        # This would use AI/ML in production
        # For now, using rule-based logic
        
        if not findings:
            return "Initial network assessment required"
        
        # Analyze patterns in findings
        error_count = sum(1 for f in findings if f.get('status') == 'error')
        warning_count = sum(1 for f in findings if f.get('status') == 'warning')
        
        if error_count > 3:
            return "Systemic network failure - possible infrastructure issue"
        elif warning_count > 5:
            return "Performance degradation - possible congestion or interference"
        elif 'security' in str(findings):
            return "Security vulnerability detected - immediate assessment required"
        else:
            return "Network operating within normal parameters"
    
    def calculate_confidence(self) -> float:
        """Calculate confidence in current hypothesis"""
        if not self.findings_so_far:
            return 0.0
            
        # Simple confidence calculation
        total_findings = len(self.findings_so_far)
        consistent_findings = sum(
            1 for f in self.findings_so_far 
            if self._is_consistent_with_hypothesis(f)
        )
        
        return (consistent_findings / total_findings) * 100
    
    def _is_consistent_with_hypothesis(self, finding: Dict) -> bool:
        """Check if finding is consistent with current hypothesis"""
        # Simplified logic - would be more sophisticated in production
        return finding.get('status') != 'error'
    
    def explain_strategy_change(self) -> str:
        """Explain why diagnostic strategy is changing"""
        return f"Based on {len(self.findings_so_far)} findings, adjusting focus to {self.current_hypothesis}"
    
    def create_additional_diagnostic_tools(self) -> List[str]:
        """Determine what additional tools are needed"""
        tools = []
        
        if "infrastructure" in self.current_hypothesis:
            tools.append("deep_packet_inspection")
            tools.append("physical_layer_analysis")
        elif "congestion" in self.current_hypothesis:
            tools.append("channel_utilization_monitor")
            tools.append("device_density_mapper")
        elif "security" in self.current_hypothesis:
            tools.append("vulnerability_scanner")
            tools.append("rogue_device_detector")
            
        return tools
    
    def build_next_diagnostic_step(self) -> Dict[str, Any]:
        """Build the next diagnostic step based on current hypothesis"""
        return {
            'hypothesis': self.current_hypothesis,
            'confidence': self.calculate_confidence(),
            'recommended_diagnostics': self.create_additional_diagnostic_tools(),
            'priority': self._determine_priority(),
            'estimated_time': self._estimate_diagnostic_time()
        }
    
    def _determine_priority(self) -> str:
        """Determine priority of next diagnostic step"""
        if "security" in self.current_hypothesis or "failure" in self.current_hypothesis:
            return "critical"
        elif "degradation" in self.current_hypothesis:
            return "high"
        else:
            return "normal"
    
    def _estimate_diagnostic_time(self) -> int:
        """Estimate time for next diagnostic step in minutes"""
        tools = self.create_additional_diagnostic_tools()
        # Rough estimate: 5 minutes per tool
        return len(tools) * 5