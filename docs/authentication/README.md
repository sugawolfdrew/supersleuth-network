# SuperSleuth Network - Authentication Framework Documentation

## Overview

SuperSleuth Network includes an **optional authentication framework** that provides enterprise-grade authentication and authorization capabilities. This is a **demo/framework implementation** - authentication is NOT required by default.

## 🎯 Key Points

### What This IS:
- ✅ A **framework** showing how authentication CAN be implemented
- ✅ **Modular functions** that Claude Code can orchestrate
- ✅ **Example code** demonstrating LDAP, AD, and local auth
- ✅ **Optional layer** that organizations can enable if needed

### What This IS NOT:
- ❌ NOT enforcing authentication by default
- ❌ NOT blocking access to any tools
- ❌ NOT connected to real auth servers
- ❌ NOT required to use SuperSleuth

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude Code                              │
│                  (Orchestrates Auth)                         │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              auth_functions.py                               │
│          (Authentication Orchestrator)                       │
├─────────────────┬───────────────┬───────────────────────────┤
│   Local Auth    │   LDAP Auth   │   AD Auth    │   OAuth2   │
│   (Working)     │   (Ready)     │   (Ready)    │  (Planned) │
└─────────────────┴───────────────┴───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              authorization.py                                │
│          (Permission & Risk Assessment)                      │
└─────────────────────────────────────────────────────────────┘
```

## Authentication Methods

### 1. Local Authentication (Implemented)
Simple username/password authentication with local user store.

```python
from src.core.auth_functions import authenticate_user

result = authenticate_user(
    username='admin',
    password='secure_password',
    method='local',
    users={
        'admin': {
            'password': 'secure_password',
            'groups': ['network_admins']
        }
    }
)
```

### 2. LDAP Authentication (Framework Ready)
Authenticate against LDAP directory services.

```python
result = authenticate_user(
    username='john.doe',
    password='ldap_password',
    method='ldap',
    server_uri='ldap://ldap.company.com',
    base_dn='dc=company,dc=com'
)
```

**Note**: Requires `pip install ldap3` to activate.

### 3. Active Directory (Framework Ready)
Full AD integration with Kerberos support and nested groups.

```python
result = authenticate_user(
    username='DOMAIN\\john.doe',  # or john.doe@domain.com
    password='ad_password',
    method='active_directory',
    domain='company.local',
    required_groups=['IT-Staff']
)
```

**Features**:
- Multiple auth formats (DOMAIN\user, user@domain)
- Kerberos support (when gssapi available)
- Nested group membership
- Domain controller discovery

### 4. OAuth2 (Planned)
Placeholder for OAuth2 provider integration (Google, Microsoft, GitHub).

## Authorization Framework

### Risk-Based Access Control

The system automatically assesses risk levels for actions:

```python
# Risk Level Assessment
LOW:      Read-only operations (view, list)
MEDIUM:   Active scanning (test, check)  
HIGH:     Configuration changes (modify, update)
CRITICAL: Destructive operations (delete, shutdown)
```

### Group-Based Permissions

```python
# Example Permission Mapping
'network_readonly':  ['view_network', 'read_diagnostics']
'network_operators': ['run_scans', 'test_connectivity'] 
'network_admins':    ['modify_config', 'perform_remediation']
'security_team':     ['run_security_scans', 'view_vulnerabilities']
```

## Implementation Guide

### Option 1: No Authentication (Default)
```python
# Just use the tools - no auth required
from src.diagnostics import network_scanner
results = network_scanner.scan()  # Works immediately
```

### Option 2: Add Authentication Wrapper
```python
# Your organization's wrapper
from src.core.auth_functions import authenticate_user

def protected_scan(username, password):
    # Authenticate first
    auth = authenticate_user(username, password, method='ldap')
    if not auth['success']:
        return "Authentication failed"
    
    # Check permissions
    if 'network_operators' not in auth['groups']:
        return "Insufficient permissions"
    
    # Proceed with scan
    return network_scanner.scan()
```

### Option 3: Claude Code Orchestration
```python
# Claude Code intelligently handles auth based on context
client_config = {
    'auth_method': 'active_directory',
    'domain': 'company.local',
    'required_groups': ['IT-Staff']
}

# Claude Code uses this config to orchestrate auth when needed
if client_needs_auth:
    apply_authentication(client_config)
```

## File Structure

```
src/core/
├── auth_functions.py          # Main orchestrator
├── auth_modules/
│   ├── __init__.py           # Module exports
│   ├── ldap_functions.py     # LDAP authentication
│   └── ad_functions.py       # Active Directory
└── authorization.py          # Enhanced with auth integration
```

## Testing Authentication

Run the demo to see authentication in action:

```bash
python examples/authentication_demo.py
```

This demonstrates:
- Checking available auth methods
- Local authentication
- LDAP examples (if available)
- AD examples (if available)
- Integration with authorization
- Claude Code orchestration patterns

## Security Considerations

### What's Implemented:
- ✅ Secure password handling (no plaintext storage)
- ✅ Group-based access control
- ✅ Audit logging capabilities
- ✅ Session management framework
- ✅ Risk assessment for actions

### What Organizations Must Add:
- 🔐 Actual password hashing (bcrypt, scrypt, etc.)
- 🔐 SSL/TLS for LDAP connections
- 🔐 Token expiration and refresh
- 🔐 Rate limiting and lockout policies
- 🔐 Integration with their security infrastructure

## FAQ

**Q: Do I need to set up authentication to use SuperSleuth?**
A: No! Authentication is completely optional. All tools work without any auth by default.

**Q: Can I use my company's Active Directory?**
A: Yes, the framework supports AD integration. You'll need to configure the connection settings and ensure network connectivity to your domain controllers.

**Q: Is this production-ready authentication?**
A: This is a framework/demo. For production use, you should add proper password hashing, SSL certificates, and integrate with your security policies.

**Q: Can Claude Code bypass authentication?**
A: No. When authentication is enabled by an organization, Claude Code must authenticate like any other user. The AI can orchestrate the auth process but cannot bypass it.

**Q: What about multi-factor authentication?**
A: The framework includes MFA placeholders. Organizations can implement TOTP, SMS, or hardware token support as needed.

## Next Steps

1. **For Testing**: Run `examples/authentication_demo.py`
2. **For Implementation**: Review auth modules in `src/core/auth_modules/`
3. **For Integration**: See `authorization.py` for auth+authz workflows
4. **For Customization**: Extend the framework for your needs

Remember: **Authentication is OPTIONAL**. SuperSleuth works perfectly without it!