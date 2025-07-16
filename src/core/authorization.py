"""
Enterprise authorization and compliance framework
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

from ..utils.logger import get_logger, get_audit_logger


class RiskLevel(Enum):
    """Risk levels for operations"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationStatus(Enum):
    """Authorization status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class AuthorizationRequest:
    """Authorization request details"""
    client_name: str
    sow_reference: str
    action: str
    scope: str
    risk_level: RiskLevel
    business_justification: str
    systems_affected: List[str]
    data_access_level: str
    execution_window: str
    estimated_duration: int  # minutes
    rollback_plan: str
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if not self.request_id:
            self.request_id = self._generate_request_id()
        if not self.timestamp:
            self.timestamp = datetime.now()
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        data = f"{self.client_name}{self.action}{datetime.now().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat(),
            'client_name': self.client_name,
            'sow_reference': self.sow_reference,
            'action': self.action,
            'scope': self.scope,
            'risk_level': self.risk_level.value,
            'business_justification': self.business_justification,
            'systems_affected': self.systems_affected,
            'data_access_level': self.data_access_level,
            'execution_window': self.execution_window,
            'estimated_duration': self.estimated_duration,
            'rollback_plan': self.rollback_plan
        }


class EnterpriseAuthorization:
    """Manages enterprise authorization workflows"""
    
    def __init__(self, client_config: Dict):
        self.client_config = client_config
        self.logger = get_logger(self.__class__.__name__)
        self.audit_logger = get_audit_logger(client_config['client_name'])
        self.pending_requests: Dict[str, AuthorizationRequest] = {}
        self.approved_requests: Dict[str, AuthorizationRequest] = {}
        self.authorization_cache_file = Path("auth_cache.json")
        self._load_authorization_cache()
    
    def request_authorization(self, request: AuthorizationRequest) -> str:
        """Request authorization for an action"""
        
        # Log authorization request
        self.audit_logger.log(
            'authorization_requested',
            request.to_dict(),
            risk_level=request.risk_level.value
        )
        
        # Check if similar request already approved
        cached_auth = self._check_cached_authorization(request)
        if cached_auth:
            self.logger.info(f"Using cached authorization: {cached_auth}")
            return cached_auth
        
        # Store pending request
        self.pending_requests[request.request_id] = request
        
        # Generate authorization prompt
        auth_prompt = self._generate_authorization_prompt(request)
        
        return auth_prompt
    
    def _generate_authorization_prompt(self, request: AuthorizationRequest) -> str:
        """Generate authorization prompt for display"""
        
        prompt = f"""
🏢 ENTERPRISE AUTHORIZATION REQUEST:
=====================================
Client: {request.client_name}
Engagement: {request.sow_reference}
Request ID: {request.request_id}

Proposed Action: {request.action}
Diagnostic Scope: {request.scope}
Systems Affected: {', '.join(request.systems_affected)}
Data Access Level: {request.data_access_level}
Execution Window: {request.execution_window}
Estimated Duration: {request.estimated_duration} minutes

Business Justification:
{request.business_justification}

Risk Assessment: {request.risk_level.value.upper()}
{self._get_risk_description(request.risk_level)}

Rollback Plan:
{request.rollback_plan}

Required Approval Level: {self._get_approval_level(request.risk_level)}

Type 'ENTERPRISE-APPROVED-{request.sow_reference}' to proceed or 'CLIENT-DENIED' to abort.
"""
        return prompt
    
    def process_authorization_response(self, response: str, request_id: str) -> bool:
        """Process authorization response"""
        
        if request_id not in self.pending_requests:
            self.logger.error(f"Unknown request ID: {request_id}")
            return False
        
        request = self.pending_requests[request_id]
        
        # Check response format
        expected_approval = f"ENTERPRISE-APPROVED-{request.sow_reference}"
        
        if response == expected_approval:
            # Approved
            self.approved_requests[request_id] = request
            del self.pending_requests[request_id]
            
            self.audit_logger.log(
                'authorization_approved',
                {
                    'request_id': request_id,
                    'approved_by': 'client_representative'
                },
                risk_level=request.risk_level.value
            )
            
            # Cache authorization
            self._cache_authorization(request)
            
            return True
            
        elif response == "CLIENT-DENIED":
            # Denied
            del self.pending_requests[request_id]
            
            self.audit_logger.log(
                'authorization_denied',
                {'request_id': request_id},
                risk_level=request.risk_level.value
            )
            
            return False
        
        else:
            self.logger.warning(f"Invalid authorization response: {response}")
            return False
    
    def check_authorization(self, action: str, scope: str) -> bool:
        """Check if an action is authorized"""
        
        # Check approved requests
        for request in self.approved_requests.values():
            if request.action == action and request.scope == scope:
                # Check if still within execution window
                if self._is_within_execution_window(request):
                    return True
        
        return False
    
    def _get_risk_description(self, risk_level: RiskLevel) -> str:
        """Get risk level description"""
        
        descriptions = {
            RiskLevel.MINIMAL: "Passive monitoring with zero system interaction",
            RiskLevel.LOW: "Read-only operations with minimal business impact",
            RiskLevel.MEDIUM: "Active scanning that may trigger security alerts",
            RiskLevel.HIGH: "Operations that could affect network performance",
            RiskLevel.CRITICAL: "Changes that could impact business operations"
        }
        
        return descriptions.get(risk_level, "Unknown risk level")
    
    def _get_approval_level(self, risk_level: RiskLevel) -> str:
        """Determine required approval level based on risk"""
        
        approval_levels = {
            RiskLevel.MINIMAL: "IT Technician",
            RiskLevel.LOW: "IT Technician",
            RiskLevel.MEDIUM: "IT Manager",
            RiskLevel.HIGH: "IT Director/CISO",
            RiskLevel.CRITICAL: "CTO/Executive Approval"
        }
        
        return approval_levels.get(risk_level, "IT Manager")
    
    def _is_within_execution_window(self, request: AuthorizationRequest) -> bool:
        """Check if current time is within authorized execution window"""
        
        # Parse execution window (simplified - in production would be more robust)
        # Format: "2024-07-15 14:00-16:00 EST"
        try:
            window_parts = request.execution_window.split()
            date_str = window_parts[0]
            time_range = window_parts[1]
            
            # For now, simplified check - always return True
            # In production, would parse and compare with current time
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing execution window: {e}")
            return False
    
    def _check_cached_authorization(self, request: AuthorizationRequest) -> Optional[str]:
        """Check if similar authorization exists in cache"""
        
        # Look for matching action and scope in cache
        cache_key = f"{request.client_name}:{request.action}:{request.scope}"
        
        if cache_key in self.authorization_cache:
            cached = self.authorization_cache[cache_key]
            # Check if not expired (24 hour cache)
            if (datetime.now() - datetime.fromisoformat(cached['timestamp'])).days < 1:
                return cached['request_id']
        
        return None
    
    def _cache_authorization(self, request: AuthorizationRequest):
        """Cache authorization for reuse"""
        
        cache_key = f"{request.client_name}:{request.action}:{request.scope}"
        self.authorization_cache[cache_key] = {
            'request_id': request.request_id,
            'timestamp': datetime.now().isoformat()
        }
        
        self._save_authorization_cache()
    
    def _load_authorization_cache(self):
        """Load authorization cache from file"""
        
        if self.authorization_cache_file.exists():
            try:
                with open(self.authorization_cache_file, 'r') as f:
                    self.authorization_cache = json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading authorization cache: {e}")
                self.authorization_cache = {}
        else:
            self.authorization_cache = {}
    
    def _save_authorization_cache(self):
        """Save authorization cache to file"""
        
        try:
            with open(self.authorization_cache_file, 'w') as f:
                json.dump(self.authorization_cache, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving authorization cache: {e}")


class ComplianceValidator:
    """Validates operations against compliance requirements"""
    
    def __init__(self, frameworks: List[str]):
        self.frameworks = frameworks
        self.logger = get_logger(self.__class__.__name__)
        
    def validate_operation(self, operation: str, data_access: str) -> Dict[str, Any]:
        """Validate operation against compliance frameworks"""
        
        validation_results = {
            'compliant': True,
            'frameworks_checked': self.frameworks,
            'violations': [],
            'warnings': []
        }
        
        for framework in self.frameworks:
            result = self._check_framework_compliance(framework, operation, data_access)
            
            if not result['compliant']:
                validation_results['compliant'] = False
                validation_results['violations'].extend(result['violations'])
            
            validation_results['warnings'].extend(result.get('warnings', []))
        
        return validation_results
    
    def _check_framework_compliance(self, framework: str, operation: str, 
                                   data_access: str) -> Dict[str, Any]:
        """Check compliance for specific framework"""
        
        # Framework-specific rules
        if framework == "PCI_DSS":
            return self._check_pci_compliance(operation, data_access)
        elif framework == "HIPAA":
            return self._check_hipaa_compliance(operation, data_access)
        elif framework == "SOC2":
            return self._check_soc2_compliance(operation, data_access)
        elif framework == "GDPR":
            return self._check_gdpr_compliance(operation, data_access)
        else:
            return {'compliant': True, 'violations': [], 'warnings': []}
    
    def _check_pci_compliance(self, operation: str, data_access: str) -> Dict[str, Any]:
        """Check PCI DSS compliance"""
        
        result = {'compliant': True, 'violations': [], 'warnings': []}
        
        # Check for cardholder data access
        if "payment" in data_access.lower() or "card" in data_access.lower():
            result['violations'].append("Direct access to payment card data requires PCI certification")
            result['compliant'] = False
        
        # Check for network segmentation
        if "scan" in operation.lower() and "production" in operation.lower():
            result['warnings'].append("Ensure cardholder data environment is properly segmented")
        
        return result
    
    def _check_hipaa_compliance(self, operation: str, data_access: str) -> Dict[str, Any]:
        """Check HIPAA compliance"""
        
        result = {'compliant': True, 'violations': [], 'warnings': []}
        
        # Check for PHI access
        if "patient" in data_access.lower() or "medical" in data_access.lower():
            result['violations'].append("Access to PHI requires HIPAA authorization")
            result['compliant'] = False
        
        # Check for audit controls
        if "monitor" in operation.lower():
            result['warnings'].append("Ensure audit logs do not capture PHI")
        
        return result
    
    def _check_soc2_compliance(self, operation: str, data_access: str) -> Dict[str, Any]:
        """Check SOC 2 compliance"""
        
        result = {'compliant': True, 'violations': [], 'warnings': []}
        
        # SOC 2 requires audit trails for all operations
        result['warnings'].append("Ensure all operations are logged with appropriate detail")
        
        # Check for change management
        if "modify" in operation.lower() or "change" in operation.lower():
            result['warnings'].append("Changes must follow approved change management process")
        
        return result
    
    def _check_gdpr_compliance(self, operation: str, data_access: str) -> Dict[str, Any]:
        """Check GDPR compliance"""
        
        result = {'compliant': True, 'violations': [], 'warnings': []}
        
        # Check for personal data access
        if "user" in data_access.lower() or "personal" in data_access.lower():
            result['warnings'].append("Ensure lawful basis for processing personal data")
        
        # Check for data retention
        if "store" in operation.lower() or "save" in operation.lower():
            result['warnings'].append("Data must be deleted after engagement per GDPR requirements")
        
        return result