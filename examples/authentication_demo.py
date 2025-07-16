#!/usr/bin/env python3
"""
SuperSleuth Network - Authentication Demo

This example demonstrates how Claude Code can orchestrate various
authentication modules for enterprise network diagnostics.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.auth_functions import (
    authenticate_user,
    get_auth_capabilities,
    create_auth_config,
    AuthenticationOrchestrator
)
from src.core.authorization import (
    authenticate_and_authorize,
    get_user_permissions
)


def demo_auth_capabilities():
    """Demonstrate checking authentication capabilities."""
    print("🔐 SuperSleuth Authentication Capabilities")
    print("=" * 60)
    
    capabilities = get_auth_capabilities()
    
    print("\n📋 Available Authentication Methods:")
    for method, info in capabilities['methods'].items():
        status = "✅" if info['available'] else "❌"
        print(f"  {status} {method.upper()}: {info['message']}")
        
        if method == 'active_directory' and info['available']:
            print(f"     - Kerberos: {'✅' if info.get('kerberos') else '❌'}")
            print(f"     - Windows Auth: {'✅' if info.get('windows_auth') else '❌'}")
    
    print("\n🔧 Feature Support:")
    for feature, enabled in capabilities['features'].items():
        status = "✅" if enabled else "❌"
        print(f"  {status} {feature.replace('_', ' ').title()}")


def demo_local_authentication():
    """Demonstrate local authentication."""
    print("\n\n🏠 Local Authentication Demo")
    print("=" * 60)
    
    # Create local user store
    local_users = {
        'admin': {
            'password': 'SecurePass123!',
            'display_name': 'System Administrator',
            'groups': ['network_admins', 'security_team']
        },
        'operator': {
            'password': 'OperatorPass456!',
            'display_name': 'Network Operator',
            'groups': ['network_operators']
        },
        'viewer': {
            'password': 'ViewerPass789!',
            'display_name': 'Read-Only User',
            'groups': ['network_readonly']
        }
    }
    
    # Test authentication for each user
    for username in ['admin', 'operator', 'viewer', 'invalid']:
        password = local_users.get(username, {}).get('password', 'wrong')
        
        result = authenticate_user(
            username=username,
            password=password,
            method='local',
            users=local_users
        )
        
        if result['success']:
            print(f"\n✅ {username}: Authentication successful")
            print(f"   Display Name: {result['user_info'].get('display_name')}")
            print(f"   Groups: {', '.join(result['groups'])}")
        else:
            print(f"\n❌ {username}: {result['errors'][0]}")


def demo_ldap_authentication():
    """Demonstrate LDAP authentication (example only)."""
    print("\n\n🌐 LDAP Authentication Demo")
    print("=" * 60)
    
    # Check if LDAP is available
    from src.core.auth_modules.ldap_functions import check_ldap_availability
    available, msg = check_ldap_availability()
    
    if not available:
        print(f"❌ LDAP not available: {msg}")
        print("   To enable LDAP support, install: pip install ldap3")
        return
    
    print("✅ LDAP support is available")
    
    # Example LDAP configuration
    print("\n📝 Example LDAP Configuration:")
    print("""
    ldap_config = {
        'server_uri': 'ldap://ldap.forumsys.com',  # Public test LDAP
        'base_dn': 'dc=example,dc=com',
        'use_ssl': False
    }
    
    # Authenticate user
    result = authenticate_user(
        username='tesla',
        password='password',
        method='ldap',
        **ldap_config
    )
    """)


def demo_ad_authentication():
    """Demonstrate Active Directory authentication (example only)."""
    print("\n\n🏢 Active Directory Authentication Demo")
    print("=" * 60)
    
    # Check AD requirements
    from src.core.auth_modules.ad_functions import check_ad_requirements
    reqs = check_ad_requirements()
    
    print("📋 AD Requirements Check:")
    for component, (available, msg) in reqs.items():
        status = "✅" if available else "❌"
        print(f"  {status} {component}: {msg}")
    
    if not reqs['ldap'][0]:
        print("\n❌ Cannot proceed without LDAP support")
        return
    
    print("\n📝 Example AD Configuration:")
    print("""
    ad_config = {
        'domain': 'company.local',
        'required_groups': ['IT-Staff', 'Network-Admins']
    }
    
    # Authenticate with different username formats
    for username in ['john.doe', 'COMPANY\\\\john.doe', 'john.doe@company.local']:
        result = authenticate_user(
            username=username,
            password='SecurePassword123!',
            method='active_directory',
            **ad_config
        )
    """)


def demo_authorization_integration():
    """Demonstrate authentication + authorization integration."""
    print("\n\n🔒 Authentication + Authorization Integration")
    print("=" * 60)
    
    # Client configuration
    client_config = {
        'client_name': 'Acme Corporation',
        'sow_reference': 'SOW-2024-001',
        'auth_method': 'local',
        'auth_config': {
            'users': {
                'admin': {
                    'password': 'AdminPass123!',
                    'groups': ['network_admins']
                },
                'user': {
                    'password': 'UserPass456!',
                    'groups': ['network_readonly']
                }
            }
        },
        'required_groups': []
    }
    
    # Test different users and actions
    test_cases = [
        ('admin', 'AdminPass123!', 'run_security_scan', '192.168.1.0/24'),
        ('user', 'UserPass456!', 'view_network_status', 'all'),
        ('user', 'UserPass456!', 'modify_firewall_rules', 'DMZ')
    ]
    
    for username, password, action, scope in test_cases:
        print(f"\n🧪 Testing: {username} → {action} on {scope}")
        
        success, msg, details = authenticate_and_authorize(
            client_config,
            username,
            password,
            action,
            scope
        )
        
        if success:
            print(f"   ✅ {msg}")
        else:
            print(f"   ❌ {msg}")
            
        # Check user permissions
        if username in ['admin', 'user']:
            perms = get_user_permissions(client_config, username)
            if perms['authorized']:
                print(f"   📋 User permissions: {', '.join(perms['permissions'][:3])}...")
                print(f"   🎚️  Allowed risk levels: {', '.join(perms['risk_levels'])}")


def demo_claude_code_orchestration():
    """Show how Claude Code would orchestrate authentication."""
    print("\n\n🤖 Claude Code Orchestration Example")
    print("=" * 60)
    
    print("""
# Example: Claude Code handling a diagnostic request with authentication

User: "I need to run a security scan on the production network"

Claude Code: I'll help you run a security scan. First, I need to authenticate you
            and verify you have the necessary permissions.

```python
# Step 1: Check authentication capabilities
capabilities = get_auth_capabilities()
print(f"Available auth methods: {list(capabilities['methods'].keys())}")

# Step 2: Authenticate user (using AD in this example)
auth_result = authenticate_user(
    username=input("Username: "),
    password=getpass.getpass("Password: "),
    method='active_directory',
    domain='company.local',
    required_groups=['Security-Team', 'Network-Admins']
)

if not auth_result['success']:
    print(f"Authentication failed: {auth_result['errors']}")
    exit(1)

# Step 3: Check authorization for security scanning
client_config = {
    'client_name': 'Company Corp',
    'auth_method': 'active_directory',
    'required_groups': ['Security-Team']
}

auth_success, msg, details = authenticate_and_authorize(
    client_config,
    auth_result['user_info']['username'],
    '<already_authenticated>',
    'run_security_scan',
    'production_network'
)

if auth_success:
    print("✅ Authorized to run security scan")
    # Proceed with security scan
    from src.diagnostics import security_scanner
    results = security_scanner.perform_security_scan('10.0.0.0/8')
else:
    print(f"❌ Authorization required: {msg}")
```

This shows how I can:
1. Check what authentication methods are available
2. Authenticate the user with appropriate method
3. Verify they have permission for the requested action
4. Only proceed with the scan if properly authorized
""")


def main():
    """Run all authentication demos."""
    print("🔐 SuperSleuth Network - Authentication System Demo")
    print("=" * 70)
    print("This demo shows how Claude Code can orchestrate authentication")
    print("and authorization for enterprise network diagnostics.")
    print("=" * 70)
    
    # Run demos
    demo_auth_capabilities()
    demo_local_authentication()
    demo_ldap_authentication()
    demo_ad_authentication()
    demo_authorization_integration()
    demo_claude_code_orchestration()
    
    print("\n\n✅ Authentication demo complete!")
    print("=" * 70)
    print("\n📚 Key Takeaways:")
    print("  • Multiple authentication methods can be orchestrated by Claude Code")
    print("  • Group-based authorization controls what users can do")
    print("  • Risk levels determine required approval levels")
    print("  • Authentication and authorization are integrated seamlessly")
    print("  • Claude Code can adapt authentication based on available methods")


if __name__ == "__main__":
    main()