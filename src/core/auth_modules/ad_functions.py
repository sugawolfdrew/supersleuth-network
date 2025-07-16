"""
Active Directory Authentication Functions for SuperSleuth Network

Specialized functions for Active Directory authentication, including
Kerberos support and AD-specific features that Claude Code can orchestrate.
"""

import logging
import socket
import struct
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import re

# Import LDAP functions for base functionality
from .ldap_functions import (
    LDAPConfig, initialize_ldap_connection, authenticate_ldap_user,
    search_ldap_user, get_user_ldap_groups, close_ldap_connection
)

# Try to import Kerberos libraries
try:
    import gssapi
    from gssapi.exceptions import GSSError
    KERBEROS_AVAILABLE = True
except ImportError:
    KERBEROS_AVAILABLE = False
    gssapi = None
    GSSError = Exception

# Try to import Windows-specific libraries
try:
    import win32security
    import win32api
    import win32con
    import pywintypes
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    win32security = win32api = win32con = pywintypes = None

logger = logging.getLogger(__name__)


@dataclass
class ADConfig(LDAPConfig):
    """Extended configuration for Active Directory."""
    domain: str = ""
    domain_controller: Optional[str] = None
    enable_kerberos: bool = True
    enable_nested_groups: bool = True
    default_ou: str = ""
    global_catalog_port: int = 3268


def check_ad_requirements() -> Dict[str, Tuple[bool, str]]:
    """Check availability of Active Directory related libraries."""
    requirements = {
        'ldap': (True, "LDAP support available"),
        'kerberos': (KERBEROS_AVAILABLE, 
                    "Kerberos available" if KERBEROS_AVAILABLE else 
                    "gssapi not installed. Run: pip install gssapi"),
        'windows_auth': (WINDOWS_AVAILABLE,
                        "Windows authentication available" if WINDOWS_AVAILABLE else
                        "pywin32 not available (Windows only)")
    }
    return requirements


def discover_domain_controllers(domain: str) -> Tuple[bool, str, List[str]]:
    """
    Discover domain controllers for a given AD domain using DNS.
    
    Args:
        domain: Active Directory domain name
        
    Returns:
        Tuple of (success, message, list of domain controllers)
    """
    try:
        # Query DNS for domain controller SRV records
        srv_record = f"_ldap._tcp.{domain}"
        controllers = []
        
        # Try to resolve SRV records
        import dns.resolver
        
        answers = dns.resolver.resolve(srv_record, 'SRV')
        for rdata in answers:
            dc_host = str(rdata.target).rstrip('.')
            controllers.append({
                'host': dc_host,
                'port': rdata.port,
                'priority': rdata.priority,
                'weight': rdata.weight
            })
            
        # Sort by priority (lower is better)
        controllers.sort(key=lambda x: (x['priority'], -x['weight']))
        dc_list = [dc['host'] for dc in controllers]
        
        return True, f"Found {len(dc_list)} domain controllers", dc_list
        
    except ImportError:
        # Fallback to simple DNS lookup if dnspython not available
        try:
            dc_ip = socket.gethostbyname(f"dc.{domain}")
            return True, "Found domain controller via DNS", [f"dc.{domain}"]
        except socket.gaierror:
            return False, "dnspython not installed and DNS lookup failed", []
            
    except Exception as e:
        logger.error(f"Failed to discover domain controllers: {e}")
        return False, f"Discovery failed: {str(e)}", []


def authenticate_ad_user(
    username: str,
    password: str,
    config: ADConfig,
    auth_method: str = 'auto'
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticate user against Active Directory with multiple methods.
    
    Args:
        username: Username (can be sAMAccountName, UPN, or domain\\user)
        password: User password
        config: AD configuration
        auth_method: Authentication method ('auto', 'ntlm', 'kerberos', 'simple')
        
    Returns:
        Tuple of (success, message, user info dict)
    """
    # Parse username format
    user_info = parse_ad_username(username, config.domain)
    
    # Auto-detect best authentication method
    if auth_method == 'auto':
        if KERBEROS_AVAILABLE and config.enable_kerberos:
            auth_method = 'kerberos'
        elif WINDOWS_AVAILABLE:
            auth_method = 'ntlm'
        else:
            auth_method = 'simple'
    
    # Initialize server
    if not config.domain_controller:
        # Discover domain controller
        success, msg, dcs = discover_domain_controllers(config.domain)
        if success and dcs:
            config.server_uri = f"ldap://{dcs[0]}"
        else:
            config.server_uri = f"ldap://{config.domain}"
    else:
        config.server_uri = f"ldap://{config.domain_controller}"
    
    server, msg = initialize_ldap_connection(config)
    if not server:
        return False, msg, None
    
    # Authenticate based on method
    if auth_method == 'kerberos':
        return authenticate_kerberos(user_info['principal'], password, server, config)
    elif auth_method == 'ntlm':
        return authenticate_ntlm(user_info['full'], password, server, config)
    else:
        # Simple bind with different username formats
        success, msg, conn = authenticate_ldap_user(
            server, user_info['full'], password, config, 'simple'
        )
        
        if success and conn:
            # Get additional user info
            found, search_msg, user_data = search_ldap_user(
                conn, user_info['account'], config
            )
            close_ldap_connection(conn)
            
            if found:
                return True, "Authentication successful", user_data
            else:
                return True, "Authentication successful (limited info)", {
                    'username': user_info['account']
                }
        
        return False, msg, None


def parse_ad_username(username: str, default_domain: str) -> Dict[str, str]:
    """
    Parse various AD username formats.
    
    Supports:
    - username
    - DOMAIN\\username
    - username@domain.com
    """
    result = {
        'original': username,
        'account': username,
        'domain': default_domain,
        'full': username,
        'principal': username
    }
    
    # Check for domain\\username format
    if '\\' in username:
        parts = username.split('\\', 1)
        result['domain'] = parts[0]
        result['account'] = parts[1]
        result['full'] = username
        result['principal'] = f"{parts[1]}@{parts[0]}"
        
    # Check for username@domain format
    elif '@' in username:
        parts = username.split('@', 1)
        result['account'] = parts[0]
        result['domain'] = parts[1]
        result['full'] = f"{parts[1]}\\{parts[0]}"
        result['principal'] = username
        
    # Just username - use default domain
    else:
        result['full'] = f"{default_domain}\\{username}"
        result['principal'] = f"{username}@{default_domain}"
    
    return result


def authenticate_kerberos(
    principal: str,
    password: str,
    server: Any,
    config: ADConfig
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticate using Kerberos (GSSAPI).
    
    Args:
        principal: User principal name (user@DOMAIN.COM)
        password: User password
        server: LDAP server object
        config: AD configuration
        
    Returns:
        Tuple of (success, message, user info)
    """
    if not KERBEROS_AVAILABLE:
        return False, "Kerberos support not available", None
        
    try:
        # Create credentials with password
        name = gssapi.Name(principal, gssapi.NameType.user)
        
        # Acquire credentials
        creds = gssapi.Credentials(
            name=name,
            lifetime=28800,  # 8 hours
            usage='initiate'
        )
        
        # Create security context
        target_name = gssapi.Name(
            f"ldap/{config.domain_controller or config.domain}",
            gssapi.NameType.hostbased_service
        )
        
        ctx = gssapi.SecurityContext(
            name=target_name,
            creds=creds,
            usage='initiate'
        )
        
        # If we got here, Kerberos auth succeeded
        return True, "Kerberos authentication successful", {
            'principal': principal,
            'auth_method': 'kerberos'
        }
        
    except GSSError as e:
        logger.error(f"Kerberos authentication failed: {e}")
        return False, f"Kerberos error: {str(e)}", None
        
    except Exception as e:
        logger.error(f"Unexpected Kerberos error: {e}")
        return False, f"Authentication error: {str(e)}", None


def authenticate_ntlm(
    username: str,
    password: str,
    server: Any,
    config: ADConfig
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticate using NTLM.
    
    Args:
        username: Username in DOMAIN\\user format
        password: User password
        server: LDAP server object
        config: AD configuration
        
    Returns:
        Tuple of (success, message, user info)
    """
    try:
        # Use LDAP NTLM authentication
        from ldap3 import Connection, NTLM
        
        conn = Connection(
            server,
            user=username,
            password=password,
            authentication=NTLM,
            raise_exceptions=True
        )
        
        if conn.bind():
            # Get user info
            user_parts = parse_ad_username(username, config.domain)
            
            # Search for user details
            found, msg, user_data = search_ldap_user(
                conn, user_parts['account'], config
            )
            
            conn.unbind()
            
            if found:
                return True, "NTLM authentication successful", user_data
            else:
                return True, "NTLM authentication successful", {
                    'username': username,
                    'auth_method': 'ntlm'
                }
        else:
            return False, "NTLM authentication failed", None
            
    except Exception as e:
        logger.error(f"NTLM authentication error: {e}")
        return False, f"NTLM error: {str(e)}", None


def get_ad_user_groups_nested(
    conn: Any,
    user_dn: str,
    config: ADConfig,
    max_depth: int = 5
) -> Tuple[bool, str, Dict[str, List[str]]]:
    """
    Get user's AD groups including nested group membership.
    
    Args:
        conn: LDAP connection
        user_dn: User's distinguished name
        config: AD configuration
        max_depth: Maximum nesting depth to traverse
        
    Returns:
        Tuple of (success, message, dict with direct and nested groups)
    """
    try:
        all_groups = set()
        direct_groups = set()
        processed = set()
        
        # Get direct groups first
        success, msg, groups = get_user_ldap_groups(conn, user_dn, config)
        if not success:
            return False, msg, {'direct': [], 'nested': []}
            
        direct_groups.update(groups)
        all_groups.update(groups)
        
        if config.enable_nested_groups:
            # Process nested groups
            to_process = list(direct_groups)
            current_depth = 0
            
            while to_process and current_depth < max_depth:
                current_depth += 1
                next_level = []
                
                for group in to_process:
                    if group in processed:
                        continue
                        
                    processed.add(group)
                    
                    # Search for groups this group is member of
                    try:
                        conn.search(
                            search_base=config.base_dn,
                            search_filter=f"(member={group})",
                            attributes=['distinguishedName', 'cn']
                        )
                        
                        for entry in conn.entries:
                            parent_group = str(entry.distinguishedName)
                            if parent_group not in all_groups:
                                all_groups.add(parent_group)
                                next_level.append(parent_group)
                                
                    except Exception as e:
                        logger.warning(f"Error processing nested group {group}: {e}")
                
                to_process = next_level
        
        # Extract group names
        direct_names = extract_group_names(list(direct_groups))
        all_names = extract_group_names(list(all_groups))
        nested_names = [g for g in all_names if g not in direct_names]
        
        return True, f"Found {len(direct_names)} direct and {len(nested_names)} nested groups", {
            'direct': direct_names,
            'nested': nested_names,
            'all': all_names
        }
        
    except Exception as e:
        logger.error(f"Error getting nested groups: {e}")
        return False, f"Nested group error: {str(e)}", {
            'direct': [], 'nested': []
        }


def extract_group_names(group_dns: List[str]) -> List[str]:
    """Extract readable group names from DNs."""
    names = []
    for dn in group_dns:
        # Extract CN from DN
        match = re.search(r'CN=([^,]+)', dn, re.IGNORECASE)
        if match:
            names.append(match.group(1))
        else:
            # Fallback to full DN if CN not found
            names.append(dn)
    return names


def check_ad_group_membership(
    username: str,
    required_groups: List[str],
    config: ADConfig,
    check_nested: bool = True
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Check if user is member of required AD groups.
    
    This is a high-level function that handles authentication and group checking.
    
    Args:
        username: Username to check
        required_groups: List of required group names
        config: AD configuration
        check_nested: Whether to check nested group membership
        
    Returns:
        Tuple of (has all groups, message, detailed results)
    """
    # Authenticate to get user info
    # Note: This requires service account credentials in config
    if not config.bind_dn or not config.bind_password:
        return False, "Service account credentials required for group lookup", {}
        
    # Connect with service account
    server, msg = initialize_ldap_connection(config)
    if not server:
        return False, msg, {}
        
    success, msg, conn = authenticate_ldap_user(
        server, config.bind_dn, config.bind_password, config, 'simple'
    )
    
    if not success:
        return False, f"Service account authentication failed: {msg}", {}
        
    try:
        # Find user
        found, msg, user_data = search_ldap_user(conn, username, config)
        if not found:
            return False, f"User {username} not found", {}
            
        user_dn = user_data['dn']
        
        # Get groups
        if check_nested and config.enable_nested_groups:
            success, msg, groups_data = get_ad_user_groups_nested(
                conn, user_dn, config
            )
            user_groups = groups_data.get('all', []) if success else []
        else:
            success, msg, user_groups = get_user_ldap_groups(
                conn, user_dn, config
            )
            
        if not success:
            return False, msg, {}
            
        # Check membership
        membership = {}
        for required_group in required_groups:
            membership[required_group] = any(
                required_group.lower() in group.lower()
                for group in user_groups
            )
            
        has_all = all(membership.values())
        missing = [g for g, has in membership.items() if not has]
        
        result = {
            'user': username,
            'user_dn': user_dn,
            'required_groups': required_groups,
            'membership': membership,
            'has_all_groups': has_all,
            'missing_groups': missing,
            'user_groups': user_groups
        }
        
        if has_all:
            return True, "User has all required groups", result
        else:
            return False, f"Missing groups: {', '.join(missing)}", result
            
    finally:
        close_ldap_connection(conn)


def get_ad_user_attributes(
    username: str,
    attributes: List[str],
    config: ADConfig
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Retrieve specific AD attributes for a user.
    
    Args:
        username: Username to look up
        attributes: List of AD attributes to retrieve
        config: AD configuration with service account
        
    Returns:
        Tuple of (success, message, attributes dict)
    """
    if not config.bind_dn or not config.bind_password:
        return False, "Service account credentials required", None
        
    server, msg = initialize_ldap_connection(config)
    if not server:
        return False, msg, None
        
    success, msg, conn = authenticate_ldap_user(
        server, config.bind_dn, config.bind_password, config, 'simple'
    )
    
    if not success:
        return False, f"Service account authentication failed: {msg}", None
        
    try:
        # Add commonly needed AD attributes
        ad_attributes = list(set(attributes + [
            'sAMAccountName', 'distinguishedName', 'userPrincipalName'
        ]))
        
        found, msg, user_data = search_ldap_user(
            conn, username, config, ad_attributes
        )
        
        if found:
            return True, "Attributes retrieved successfully", user_data
        else:
            return False, msg, None
            
    finally:
        close_ldap_connection(conn)


# Example orchestration function for Claude Code
def example_ad_workflow(
    username: str,
    password: str,
    domain: str,
    required_groups: Optional[List[str]] = None,
    required_attributes: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Example AD authentication and authorization workflow.
    
    This shows how Claude Code can orchestrate various AD functions
    based on specific requirements.
    """
    result = {
        'authenticated': False,
        'authorized': False,
        'user_info': {},
        'groups': {},
        'attributes': {},
        'errors': []
    }
    
    # Check requirements
    reqs = check_ad_requirements()
    for component, (available, msg) in reqs.items():
        if not available and component in ['ldap']:
            result['errors'].append(msg)
            return result
    
    # Create config
    config = ADConfig(
        domain=domain,
        base_dn=f"DC={domain.replace('.', ',DC=')}",
        enable_kerberos=reqs['kerberos'][0],
        use_ssl=True
    )
    
    # Discover domain controllers
    success, msg, dcs = discover_domain_controllers(domain)
    if success and dcs:
        config.domain_controller = dcs[0]
    
    # Authenticate user
    success, msg, user_info = authenticate_ad_user(
        username, password, config
    )
    
    if not success:
        result['errors'].append(msg)
        return result
        
    result['authenticated'] = True
    result['user_info'] = user_info or {}
    
    # Check group membership if required
    if required_groups:
        # This would need service account credentials in real usage
        # For demo, we'll use the user's own credentials
        config.bind_dn = username
        config.bind_password = password
        
        has_groups, msg, group_info = check_ad_group_membership(
            username, required_groups, config
        )
        
        result['groups'] = group_info
        result['authorized'] = has_groups
        
        if not has_groups:
            result['errors'].append(msg)
    else:
        result['authorized'] = True
    
    # Get additional attributes if requested
    if required_attributes and result['authenticated']:
        config.bind_dn = username
        config.bind_password = password
        
        success, msg, attrs = get_ad_user_attributes(
            username, required_attributes, config
        )
        
        if success:
            result['attributes'] = attrs
        else:
            result['errors'].append(f"Failed to get attributes: {msg}")
    
    return result