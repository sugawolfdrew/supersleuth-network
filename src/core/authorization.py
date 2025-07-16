"""
Enterprise authorization and compliance framework

This module provides authorization controls that integrate with the
authentication functions in auth_functions.py and auth_modules/.
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

from ..utils.logger import get_logger, get_audit_logger
from .auth_functions import (
    authenticate_user,
    check_user_authorization,
    get_auth_capabilities
)


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
    """Manages enterprise authorization workflows with authentication integration"""
    
    def __init__(self, client_config: Dict):
        self.client_config = client_config
        self.logger = get_logger(self.__class__.__name__)
        self.audit_logger = get_audit_logger(client_config['client_name'])
        self.pending_requests: Dict[str, AuthorizationRequest] = {}
        self.approved_requests: Dict[str, AuthorizationRequest] = {}
        self.authorization_cache_file = Path("auth_cache.json")
        self._load_authorization_cache()
        
        # Authentication configuration
        self.auth_method = client_config.get('auth_method', 'local')
        self.auth_config = client_config.get('auth_config', {})
        self.required_groups = client_config.get('required_groups', [])
    
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
    
# Add authentication integration functions at module level

def authenticate_and_authorize(
    client_config: Dict,
    username: str,
    password: str,
    action: str,
    scope: str
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticate user and check authorization for specific action.
    
    This integrates authentication with authorization, allowing Claude Code
    to orchestrate both in a single workflow.
    
    Args:
        client_config: Client configuration with auth settings
        username: User identifier
        password: User password or token
        action: Action to authorize
        scope: Scope of the action
        
    Returns:
        Tuple of (success, message, auth_details)
    """
    # Extract auth config
    auth_method = client_config.get('auth_method', 'local')
    auth_config = client_config.get('auth_config', {})
    required_groups = client_config.get('required_groups', [])
    
    # Step 1: Authenticate user
    auth_result = authenticate_user(
        username=username,
        password=password,
        method=auth_method,
        required_groups=required_groups,
        **auth_config
    )
    
    if not auth_result['success']:
        return False, "Authentication failed", auth_result
    
    if not auth_result.get('authorized', False):
        missing_groups = [g for g in required_groups 
                        if g not in auth_result.get('groups', [])]
        return False, f"Missing required groups: {', '.join(missing_groups)}", auth_result
    
    # Step 2: Create authorization instance
    auth_instance = EnterpriseAuthorization(client_config)
    
    # Step 3: Check if action is pre-authorized
    if auth_instance.check_authorization(action, scope):
        return True, "Action pre-authorized", auth_result
    
    # Step 4: Create authorization request
    risk_level = _assess_risk_level(action, scope)
    
    auth_request = AuthorizationRequest(
        client_name=client_config['client_name'],
        sow_reference=client_config.get('sow_reference', 'N/A'),
        action=action,
        scope=scope,
        risk_level=risk_level,
        business_justification=f"Requested by authenticated user: {username}",
        systems_affected=[scope],
        data_access_level="Read-only" if "read" in action.lower() else "Read-write",
        execution_window="Immediate",
        estimated_duration=30,
        rollback_plan="No changes will be made" if "read" in action.lower() else "Manual rollback required"
    )
    
    # Step 5: Request authorization
    auth_prompt = auth_instance.request_authorization(auth_request)
    
    return False, f"Authorization required: {auth_request.request_id}", {
        'auth_result': auth_result,
        'auth_request': auth_request.to_dict(),
        'prompt': auth_prompt
    }


def _assess_risk_level(action: str, scope: str) -> RiskLevel:
    """Assess risk level based on action and scope"""
    action_lower = action.lower()
    
    if any(word in action_lower for word in ['read', 'view', 'list', 'get']):
        return RiskLevel.LOW
    elif any(word in action_lower for word in ['scan', 'test', 'check']):
        return RiskLevel.MEDIUM
    elif any(word in action_lower for word in ['modify', 'update', 'configure']):
        return RiskLevel.HIGH
    elif any(word in action_lower for word in ['delete', 'remove', 'shutdown']):
        return RiskLevel.CRITICAL
    else:
        return RiskLevel.MEDIUM


def get_user_permissions(
    client_config: Dict,
    username: str
) -> Dict[str, Any]:
    """
    Get user's permissions based on group membership.
    
    This allows Claude Code to understand what a user can do
    based on their authentication and group membership.
    """
    auth_method = client_config.get('auth_method', 'local')
    auth_config = client_config.get('auth_config', {})
    
    # Check user's groups
    auth_check = check_user_authorization(
        username=username,
        required_groups=[],  # Get all groups
        auth_method=auth_method,
        **auth_config
    )
    
    if not auth_check.get('authorized', False):
        return {
            'authorized': False,
            'permissions': [],
            'message': 'User not found or not authorized'
        }
    
    # Map groups to permissions
    user_groups = auth_check.get('details', {}).get('user_groups', [])
    permissions = _map_groups_to_permissions(user_groups)
    
    return {
        'authorized': True,
        'groups': user_groups,
        'permissions': permissions,
        'risk_levels': _get_allowed_risk_levels(user_groups)
    }


def _map_groups_to_permissions(groups: List[str]) -> List[str]:
    """Map user groups to permissions"""
    permissions = []
    
    # Example group to permission mapping
    group_permissions = {
        'network_readonly': ['view_network', 'read_diagnostics'],
        'network_operators': ['view_network', 'read_diagnostics', 'run_scans'],
        'network_admins': ['view_network', 'read_diagnostics', 'run_scans', 
                          'modify_config', 'perform_remediation'],
        'security_team': ['view_network', 'read_diagnostics', 'run_security_scans',
                         'view_vulnerabilities'],
        'domain admins': ['all_permissions']
    }
    
    for group in groups:
        group_lower = group.lower()
        for mapped_group, perms in group_permissions.items():
            if mapped_group in group_lower:
                permissions.extend(perms)
    
    # Remove duplicates
    return list(set(permissions))


def _get_allowed_risk_levels(groups: List[str]) -> List[str]:
    """Get allowed risk levels based on user groups"""
    # Admin groups can approve higher risk
    admin_groups = ['admins', 'administrators', 'network_admins', 'domain admins']
    manager_groups = ['managers', 'supervisors', 'team_leads']
    
    groups_lower = [g.lower() for g in groups]
    
    if any(admin in group for admin in admin_groups for group in groups_lower):
        return [level.value for level in RiskLevel]
    elif any(manager in group for manager in manager_groups for group in groups_lower):
        return [RiskLevel.MINIMAL.value, RiskLevel.LOW.value, RiskLevel.MEDIUM.value]
    else:
        return [RiskLevel.MINIMAL.value, RiskLevel.LOW.value]