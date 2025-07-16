"""
Authentication Modules for SuperSleuth Network

This package contains modular authentication functions that Claude Code
can orchestrate for various authentication and authorization needs.
"""

# Import main functions from each module for easy access
from .ldap_functions import (
    check_ldap_availability,
    initialize_ldap_connection,
    authenticate_ldap_user,
    search_ldap_user,
    get_user_ldap_groups,
    validate_group_membership,
    LDAPConfig
)

from .ad_functions import (
    check_ad_requirements,
    discover_domain_controllers,
    authenticate_ad_user,
    parse_ad_username,
    get_ad_user_groups_nested,
    check_ad_group_membership,
    get_ad_user_attributes,
    ADConfig
)

__all__ = [
    # LDAP functions
    'check_ldap_availability',
    'initialize_ldap_connection', 
    'authenticate_ldap_user',
    'search_ldap_user',
    'get_user_ldap_groups',
    'validate_group_membership',
    'LDAPConfig',
    
    # AD functions
    'check_ad_requirements',
    'discover_domain_controllers',
    'authenticate_ad_user',
    'parse_ad_username',
    'get_ad_user_groups_nested',
    'check_ad_group_membership',
    'get_ad_user_attributes',
    'ADConfig'
]