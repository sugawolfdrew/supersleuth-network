"""
LDAP Authentication Functions for SuperSleuth Network

Modular LDAP authentication functions that Claude Code can orchestrate
for enterprise user authentication using directory credentials.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import ssl
import re

# Note: ldap3 is used instead of python-ldap for better cross-platform support
try:
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, Tls
    from ldap3.core.exceptions import LDAPException, LDAPBindError
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    Server = Connection = ALL = NTLM = SIMPLE = SASL = Tls = None
    LDAPException = LDAPBindError = Exception

logger = logging.getLogger(__name__)


@dataclass
class LDAPConfig:
    """Configuration for LDAP connection."""
    server_uri: str
    port: int = 389
    use_ssl: bool = False
    validate_cert: bool = True
    timeout: int = 30
    base_dn: str = ""
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None


def check_ldap_availability() -> Tuple[bool, str]:
    """Check if LDAP libraries are available."""
    if not LDAP_AVAILABLE:
        return False, "ldap3 library not installed. Run: pip install ldap3"
    return True, "LDAP support available"


def initialize_ldap_connection(config: LDAPConfig) -> Tuple[Optional[Server], str]:
    """
    Initialize an LDAP server object with proper configuration.
    
    Args:
        config: LDAP configuration object
        
    Returns:
        Tuple of (Server object or None, status message)
    """
    try:
        # Configure TLS if using SSL
        tls_config = None
        if config.use_ssl:
            tls_config = Tls(
                validate=ssl.CERT_REQUIRED if config.validate_cert else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS
            )
        
        # Create server object
        server = Server(
            config.server_uri,
            port=config.port,
            use_ssl=config.use_ssl,
            tls=tls_config,
            get_info=ALL,
            connect_timeout=config.timeout
        )
        
        return server, "LDAP server object initialized successfully"
        
    except Exception as e:
        logger.error(f"Failed to initialize LDAP server: {e}")
        return None, f"Failed to initialize LDAP server: {str(e)}"


def test_ldap_connectivity(server: Server, config: LDAPConfig) -> Tuple[bool, str]:
    """
    Test basic connectivity to LDAP server.
    
    Args:
        server: LDAP server object
        config: LDAP configuration
        
    Returns:
        Tuple of (success boolean, status message)
    """
    try:
        # Try anonymous bind first to test connectivity
        conn = Connection(
            server,
            auto_bind=True,
            client_strategy='SYNC',
            raise_exceptions=True
        )
        conn.unbind()
        return True, f"Successfully connected to LDAP server at {config.server_uri}"
        
    except Exception as e:
        return False, f"Failed to connect to LDAP server: {str(e)}"


def authenticate_ldap_user(
    server: Server,
    username: str,
    password: str,
    config: LDAPConfig,
    auth_type: str = 'simple'
) -> Tuple[bool, str, Optional[Connection]]:
    """
    Authenticate a user against LDAP directory.
    
    Args:
        server: LDAP server object
        username: Username to authenticate
        password: User password
        config: LDAP configuration
        auth_type: Authentication type ('simple', 'ntlm', 'sasl')
        
    Returns:
        Tuple of (success, message, connection object if successful)
    """
    try:
        # Construct user DN based on configuration
        if auth_type == 'simple':
            # Different DN formats for different LDAP implementations
            if '@' in username:
                # User provided email format
                user_dn = username
            elif config.base_dn:
                # Try common DN formats
                user_dn = f"uid={username},{config.base_dn}"
                # Alternative format: cn=username,base_dn
            else:
                user_dn = username
                
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                raise_exceptions=True
            )
            
        elif auth_type == 'ntlm':
            # NTLM authentication for Active Directory
            conn = Connection(
                server,
                user=username,
                password=password,
                authentication=NTLM,
                raise_exceptions=True
            )
            
        else:
            return False, f"Unsupported authentication type: {auth_type}", None
            
        # Attempt to bind
        if conn.bind():
            logger.info(f"Successfully authenticated user: {username}")
            return True, "Authentication successful", conn
        else:
            return False, "Authentication failed", None
            
    except LDAPBindError as e:
        logger.warning(f"Invalid credentials for user {username}: {e}")
        return False, "Invalid credentials", None
        
    except Exception as e:
        logger.error(f"LDAP authentication error for user {username}: {e}")
        return False, f"Authentication error: {str(e)}", None


def search_ldap_user(
    conn: Connection,
    username: str,
    config: LDAPConfig,
    attributes: Optional[List[str]] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Search for a user in LDAP directory and retrieve their attributes.
    
    Args:
        conn: Authenticated LDAP connection
        username: Username to search for
        config: LDAP configuration
        attributes: List of attributes to retrieve (None for all)
        
    Returns:
        Tuple of (found, message, user attributes dict)
    """
    try:
        # Default attributes if none specified
        if attributes is None:
            attributes = [
                'cn', 'mail', 'memberOf', 'displayName',
                'sAMAccountName', 'userPrincipalName',
                'givenName', 'sn', 'department', 'title'
            ]
        
        # Construct search filter
        search_filter = f"(|(uid={username})(cn={username})(sAMAccountName={username})(mail={username}))"
        
        # Perform search
        conn.search(
            search_base=config.base_dn,
            search_filter=search_filter,
            attributes=attributes
        )
        
        if not conn.entries:
            return False, f"User {username} not found", None
            
        # Get first result
        user_entry = conn.entries[0]
        user_data = {
            'dn': str(user_entry.entry_dn),
            'attributes': {}
        }
        
        # Extract attributes
        for attr in attributes:
            if hasattr(user_entry, attr):
                value = getattr(user_entry, attr)
                if value:
                    user_data['attributes'][attr] = str(value) if len(value) == 1 else [str(v) for v in value]
        
        return True, f"Found user {username}", user_data
        
    except Exception as e:
        logger.error(f"LDAP search error: {e}")
        return False, f"Search error: {str(e)}", None


def get_user_ldap_groups(
    conn: Connection,
    user_dn: str,
    config: LDAPConfig
) -> Tuple[bool, str, List[str]]:
    """
    Retrieve user groups from LDAP directory.
    
    Args:
        conn: Authenticated LDAP connection
        user_dn: User's distinguished name
        config: LDAP configuration
        
    Returns:
        Tuple of (success, message, list of group DNs)
    """
    try:
        # Search for user's memberOf attribute
        conn.search(
            search_base=user_dn,
            search_filter='(objectClass=*)',
            attributes=['memberOf']
        )
        
        if not conn.entries:
            return False, "User not found", []
            
        user_entry = conn.entries[0]
        groups = []
        
        if hasattr(user_entry, 'memberOf') and user_entry.memberOf:
            groups = [str(group) for group in user_entry.memberOf]
            
        # Extract group names from DNs
        group_names = []
        for group_dn in groups:
            # Extract CN from DN
            cn_match = re.match(r'^CN=([^,]+)', group_dn, re.IGNORECASE)
            if cn_match:
                group_names.append(cn_match.group(1))
            else:
                group_names.append(group_dn)
                
        return True, f"Found {len(group_names)} groups", group_names
        
    except Exception as e:
        logger.error(f"Error retrieving user groups: {e}")
        return False, f"Group retrieval error: {str(e)}", []


def validate_group_membership(
    conn: Connection,
    user_dn: str,
    required_groups: List[str],
    config: LDAPConfig
) -> Tuple[bool, str, Dict[str, bool]]:
    """
    Validate if user is member of required groups.
    
    Args:
        conn: Authenticated LDAP connection
        user_dn: User's distinguished name
        required_groups: List of required group names
        config: LDAP configuration
        
    Returns:
        Tuple of (has all groups, message, dict of group membership)
    """
    try:
        success, message, user_groups = get_user_ldap_groups(conn, user_dn, config)
        
        if not success:
            return False, message, {}
            
        # Check membership for each required group
        membership = {}
        for required_group in required_groups:
            # Case-insensitive comparison
            membership[required_group] = any(
                required_group.lower() in group.lower()
                for group in user_groups
            )
        
        # Check if user has all required groups
        has_all = all(membership.values())
        missing_groups = [g for g, has in membership.items() if not has]
        
        if has_all:
            return True, "User has all required groups", membership
        else:
            return False, f"User missing groups: {', '.join(missing_groups)}", membership
            
    except Exception as e:
        logger.error(f"Error validating group membership: {e}")
        return False, f"Validation error: {str(e)}", {}


def close_ldap_connection(conn: Optional[Connection]) -> Tuple[bool, str]:
    """
    Safely close LDAP connection.
    
    Args:
        conn: LDAP connection object
        
    Returns:
        Tuple of (success, message)
    """
    try:
        if conn and conn.bound:
            conn.unbind()
            return True, "LDAP connection closed successfully"
        return True, "No active connection to close"
        
    except Exception as e:
        logger.error(f"Error closing LDAP connection: {e}")
        return False, f"Failed to close connection: {str(e)}"


# Example usage function for Claude Code orchestration
def example_ldap_authentication_workflow(
    server_uri: str,
    username: str,
    password: str,
    required_groups: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Example workflow showing how Claude Code can orchestrate LDAP authentication.
    
    This demonstrates the modular approach where each function can be called
    independently based on specific requirements.
    """
    result = {
        'authenticated': False,
        'user_info': None,
        'groups': [],
        'errors': []
    }
    
    # Step 1: Check LDAP availability
    available, msg = check_ldap_availability()
    if not available:
        result['errors'].append(msg)
        return result
        
    # Step 2: Initialize configuration
    config = LDAPConfig(
        server_uri=server_uri,
        use_ssl=True if 'ldaps://' in server_uri else False
    )
    
    # Step 3: Initialize server
    server, msg = initialize_ldap_connection(config)
    if not server:
        result['errors'].append(msg)
        return result
        
    # Step 4: Test connectivity
    connected, msg = test_ldap_connectivity(server, config)
    if not connected:
        result['errors'].append(msg)
        return result
        
    # Step 5: Authenticate user
    authenticated, msg, conn = authenticate_ldap_user(
        server, username, password, config
    )
    
    if not authenticated:
        result['errors'].append(msg)
        return result
        
    result['authenticated'] = True
    
    # Step 6: Get user information
    found, msg, user_data = search_ldap_user(conn, username, config)
    if found:
        result['user_info'] = user_data
        
        # Step 7: Get groups if user found
        if user_data:
            success, msg, groups = get_user_ldap_groups(
                conn, user_data['dn'], config
            )
            if success:
                result['groups'] = groups
                
                # Step 8: Validate required groups if specified
                if required_groups:
                    has_all, msg, membership = validate_group_membership(
                        conn, user_data['dn'], required_groups, config
                    )
                    result['group_validation'] = {
                        'required': required_groups,
                        'membership': membership,
                        'authorized': has_all
                    }
    
    # Step 9: Clean up
    close_ldap_connection(conn)
    
    return result