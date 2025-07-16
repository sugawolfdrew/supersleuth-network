"""
Script Scanning Module for Claude Code Orchestration

This module provides script-based vulnerability and service analysis capabilities,
similar to nmap's NSE (Nmap Scripting Engine) but with Python-based implementations.
"""

import socket
import ssl
import subprocess
import json
import re
import time
import urllib.parse
import base64
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import concurrent.futures
import requests

from ..utils.logger import get_logger

logger = get_logger(__name__)


# Script categories
SCRIPT_CATEGORIES = {
    'auth': 'Authentication related scripts',
    'default': 'Scripts run by default',
    'discovery': 'Service discovery scripts',
    'dos': 'Denial of service scripts (use with caution)',
    'exploit': 'Exploitation scripts (use with caution)',
    'fuzzer': 'Fuzzing scripts',
    'intrusive': 'Intrusive scripts that may crash services',
    'malware': 'Malware detection scripts',
    'safe': 'Safe scripts with no side effects',
    'version': 'Version detection scripts',
    'vuln': 'Vulnerability detection scripts'
}


def scan_http_vulnerabilities(host: str, port: int = 80, ssl_enabled: bool = False,
                            timeout: float = 10.0) -> Dict[str, Any]:
    """
    Scan for common HTTP/HTTPS vulnerabilities and misconfigurations.
    
    Args:
        host: Target hostname or IP address
        port: HTTP/HTTPS port
        ssl_enabled: Whether to use HTTPS
        timeout: Request timeout
        
    Returns:
        Dictionary with vulnerability findings
        
    Example:
        >>> vulns = scan_http_vulnerabilities('example.com', 443, ssl_enabled=True)
        >>> print(vulns['security_headers'])
    """
    result = {
        'host': host,
        'port': port,
        'protocol': 'https' if ssl_enabled else 'http',
        'vulnerabilities': [],
        'security_headers': {},
        'misconfigurations': [],
        'timestamp': datetime.now().isoformat()
    }
    
    base_url = f"{'https' if ssl_enabled else 'http'}://{host}:{port}"
    
    # Check security headers
    headers_result = _check_security_headers(base_url, timeout)
    result['security_headers'] = headers_result['headers']
    result['vulnerabilities'].extend(headers_result['issues'])
    
    # Check for common misconfigurations
    misconfig_result = _check_http_misconfigurations(base_url, timeout)
    result['misconfigurations'] = misconfig_result['misconfigurations']
    result['vulnerabilities'].extend(misconfig_result['vulnerabilities'])
    
    # Check for information disclosure
    info_result = _check_information_disclosure(base_url, timeout)
    result['vulnerabilities'].extend(info_result['vulnerabilities'])
    
    # Check HTTP methods
    methods_result = _check_http_methods(host, port, ssl_enabled, timeout)
    if methods_result['dangerous_methods']:
        result['vulnerabilities'].append({
            'type': 'dangerous_http_methods',
            'severity': 'medium',
            'description': f"Dangerous HTTP methods enabled: {', '.join(methods_result['dangerous_methods'])}",
            'methods': methods_result['dangerous_methods']
        })
        
    return result


def scan_ssl_vulnerabilities(host: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Scan for SSL/TLS vulnerabilities and misconfigurations.
    
    Args:
        host: Target hostname or IP address
        port: SSL/TLS port
        timeout: Connection timeout
        
    Returns:
        Dictionary with SSL/TLS vulnerability findings
    """
    result = {
        'host': host,
        'port': port,
        'vulnerabilities': [],
        'certificate_info': {},
        'supported_protocols': [],
        'supported_ciphers': [],
        'timestamp': datetime.now().isoformat()
    }
    
    # Check certificate
    cert_result = _check_ssl_certificate(host, port, timeout)
    result['certificate_info'] = cert_result['certificate']
    result['vulnerabilities'].extend(cert_result['issues'])
    
    # Check supported protocols
    protocols_result = _check_ssl_protocols(host, port, timeout)
    result['supported_protocols'] = protocols_result['supported']
    if protocols_result['weak_protocols']:
        result['vulnerabilities'].append({
            'type': 'weak_ssl_protocols',
            'severity': 'high',
            'description': f"Weak SSL/TLS protocols supported: {', '.join(protocols_result['weak_protocols'])}",
            'protocols': protocols_result['weak_protocols']
        })
        
    # Check cipher suites
    ciphers_result = _check_ssl_ciphers(host, port, timeout)
    result['supported_ciphers'] = ciphers_result['supported']
    if ciphers_result['weak_ciphers']:
        result['vulnerabilities'].append({
            'type': 'weak_ssl_ciphers',
            'severity': 'medium',
            'description': f"Weak cipher suites supported: {len(ciphers_result['weak_ciphers'])} found",
            'ciphers': ciphers_result['weak_ciphers']
        })
        
    return result


def scan_default_credentials(host: str, services: List[Dict[str, Any]], 
                           timeout: float = 5.0) -> Dict[str, Any]:
    """
    Check for default credentials on detected services.
    
    Args:
        host: Target hostname or IP address
        services: List of detected services
        timeout: Connection timeout
        
    Returns:
        Dictionary with default credential findings
        
    Warning:
        This function attempts authentication. Use only with authorization.
    """
    result = {
        'host': host,
        'vulnerabilities': [],
        'tested_services': [],
        'timestamp': datetime.now().isoformat()
    }
    
    # Common default credentials
    DEFAULT_CREDS = {
        'ssh': [
            ('root', 'root'),
            ('root', 'toor'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('user', 'user')
        ],
        'ftp': [
            ('anonymous', 'anonymous'),
            ('ftp', 'ftp'),
            ('admin', 'admin'),
            ('root', 'root')
        ],
        'mysql': [
            ('root', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('admin', 'admin')
        ],
        'postgresql': [
            ('postgres', 'postgres'),
            ('postgres', 'password'),
            ('admin', 'admin')
        ],
        'telnet': [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', 'password')
        ]
    }
    
    for service in services:
        service_name = service.get('service', '').lower()
        port = service.get('port')
        
        if service_name in DEFAULT_CREDS and service.get('state') == 'open':
            result['tested_services'].append(f"{service_name}:{port}")
            
            # Test credentials based on service type
            if service_name == 'ssh':
                ssh_result = _test_ssh_credentials(host, port, DEFAULT_CREDS['ssh'], timeout)
                if ssh_result['vulnerable']:
                    result['vulnerabilities'].append(ssh_result)
                    
            elif service_name == 'ftp':
                ftp_result = _test_ftp_credentials(host, port, DEFAULT_CREDS['ftp'], timeout)
                if ftp_result['vulnerable']:
                    result['vulnerabilities'].append(ftp_result)
                    
            # Add more service-specific tests as needed
            
    return result


def scan_database_security(host: str, port: int, db_type: str, 
                         timeout: float = 5.0) -> Dict[str, Any]:
    """
    Scan database services for security issues.
    
    Args:
        host: Target hostname or IP address
        port: Database port
        db_type: Type of database (mysql, postgresql, mongodb, etc.)
        timeout: Connection timeout
        
    Returns:
        Dictionary with database security findings
    """
    result = {
        'host': host,
        'port': port,
        'database_type': db_type,
        'vulnerabilities': [],
        'configuration_issues': [],
        'timestamp': datetime.now().isoformat()
    }
    
    if db_type.lower() == 'mysql':
        mysql_result = _scan_mysql_security(host, port, timeout)
        result['vulnerabilities'].extend(mysql_result['vulnerabilities'])
        result['configuration_issues'].extend(mysql_result['config_issues'])
        
    elif db_type.lower() == 'postgresql':
        postgres_result = _scan_postgresql_security(host, port, timeout)
        result['vulnerabilities'].extend(postgres_result['vulnerabilities'])
        result['configuration_issues'].extend(postgres_result['config_issues'])
        
    elif db_type.lower() == 'mongodb':
        mongo_result = _scan_mongodb_security(host, port, timeout)
        result['vulnerabilities'].extend(mongo_result['vulnerabilities'])
        result['configuration_issues'].extend(mongo_result['config_issues'])
        
    elif db_type.lower() == 'redis':
        redis_result = _scan_redis_security(host, port, timeout)
        result['vulnerabilities'].extend(redis_result['vulnerabilities'])
        result['configuration_issues'].extend(redis_result['config_issues'])
        
    return result


def scan_smb_vulnerabilities(host: str, port: int = 445, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Scan for SMB/NetBIOS vulnerabilities.
    
    Args:
        host: Target hostname or IP address
        port: SMB port (usually 445 or 139)
        timeout: Connection timeout
        
    Returns:
        Dictionary with SMB vulnerability findings
    """
    result = {
        'host': host,
        'port': port,
        'vulnerabilities': [],
        'smb_version': None,
        'shares': [],
        'timestamp': datetime.now().isoformat()
    }
    
    # Check SMB version and signing
    smb_info = _check_smb_version(host, port, timeout)
    result['smb_version'] = smb_info.get('version')
    
    if smb_info.get('signing_not_required'):
        result['vulnerabilities'].append({
            'type': 'smb_signing_disabled',
            'severity': 'medium',
            'description': 'SMB signing is not required, vulnerable to relay attacks'
        })
        
    # Check for SMBv1
    if smb_info.get('version') == 'SMBv1':
        result['vulnerabilities'].append({
            'type': 'smbv1_enabled',
            'severity': 'high',
            'description': 'SMBv1 is enabled, vulnerable to various attacks including EternalBlue'
        })
        
    # Try to enumerate shares (safely)
    shares_result = _enumerate_smb_shares(host, port, timeout)
    result['shares'] = shares_result['shares']
    if shares_result['anonymous_access']:
        result['vulnerabilities'].append({
            'type': 'smb_anonymous_access',
            'severity': 'medium',
            'description': 'Anonymous access to SMB shares is allowed',
            'shares': shares_result['anonymous_shares']
        })
        
    return result


def run_script_category(host: str, services: List[Dict[str, Any]], 
                       category: str = 'safe', timeout: float = 30.0) -> Dict[str, Any]:
    """
    Run all scripts in a specific category.
    
    Args:
        host: Target hostname or IP address
        services: List of detected services
        category: Script category to run
        timeout: Overall timeout for all scripts
        
    Returns:
        Dictionary with combined results from all scripts in category
    """
    if category not in SCRIPT_CATEGORIES:
        raise ValueError(f"Invalid category: {category}. Valid categories: {list(SCRIPT_CATEGORIES.keys())}")
        
    result = {
        'host': host,
        'category': category,
        'scripts_run': [],
        'vulnerabilities': [],
        'findings': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # Map categories to appropriate scripts
    if category == 'safe' or category == 'default':
        # Run non-intrusive scripts
        for service in services:
            if service.get('service') == 'HTTP' or service.get('service') == 'HTTPS':
                http_result = scan_http_vulnerabilities(
                    host, service['port'], 
                    ssl_enabled=(service['service'] == 'HTTPS'),
                    timeout=timeout/len(services)
                )
                result['scripts_run'].append('http-vuln-scan')
                result['vulnerabilities'].extend(http_result['vulnerabilities'])
                result['findings']['http'] = http_result
                
            elif service.get('port') in [443, 8443] or service.get('service') == 'HTTPS':
                ssl_result = scan_ssl_vulnerabilities(host, service['port'], timeout=timeout/len(services))
                result['scripts_run'].append('ssl-vuln-scan')
                result['vulnerabilities'].extend(ssl_result['vulnerabilities'])
                result['findings']['ssl'] = ssl_result
                
    elif category == 'vuln':
        # Run vulnerability detection scripts
        for service in services:
            if service.get('service') in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']:
                db_result = scan_database_security(
                    host, service['port'], 
                    service['service'], 
                    timeout=timeout/len(services)
                )
                result['scripts_run'].append(f"{service['service'].lower()}-vuln-scan")
                result['vulnerabilities'].extend(db_result['vulnerabilities'])
                result['findings'][service['service'].lower()] = db_result
                
            elif service.get('service') == 'SMB' or service.get('port') in [445, 139]:
                smb_result = scan_smb_vulnerabilities(host, service['port'], timeout=timeout/len(services))
                result['scripts_run'].append('smb-vuln-scan')
                result['vulnerabilities'].extend(smb_result['vulnerabilities'])
                result['findings']['smb'] = smb_result
                
    elif category == 'auth':
        # Run authentication scripts (use with caution)
        creds_result = scan_default_credentials(host, services, timeout)
        result['scripts_run'].append('default-credentials-scan')
        result['vulnerabilities'].extend(creds_result['vulnerabilities'])
        result['findings']['credentials'] = creds_result
        
    return result


# Helper functions for HTTP scanning

def _check_security_headers(base_url: str, timeout: float) -> Dict[str, Any]:
    """Check for security headers."""
    result = {'headers': {}, 'issues': []}
    
    try:
        response = requests.head(base_url, timeout=timeout, verify=False, allow_redirects=True)
        
        # Security headers to check
        security_headers = {
            'strict-transport-security': {'required': True, 'name': 'HSTS'},
            'x-frame-options': {'required': True, 'name': 'Clickjacking Protection'},
            'x-content-type-options': {'required': True, 'name': 'Content Type Options'},
            'x-xss-protection': {'required': False, 'name': 'XSS Protection'},  # Deprecated but still checked
            'content-security-policy': {'required': True, 'name': 'CSP'},
            'referrer-policy': {'required': False, 'name': 'Referrer Policy'},
            'permissions-policy': {'required': False, 'name': 'Permissions Policy'}
        }
        
        for header, info in security_headers.items():
            value = response.headers.get(header)
            result['headers'][header] = value
            
            if not value and info['required']:
                result['issues'].append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': f"Missing security header: {info['name']} ({header})",
                    'header': header
                })
                
    except Exception as e:
        logger.error(f"Error checking security headers: {e}")
        
    return result


def _check_http_misconfigurations(base_url: str, timeout: float) -> Dict[str, Any]:
    """Check for common HTTP misconfigurations."""
    result = {'misconfigurations': [], 'vulnerabilities': []}
    
    # Check for directory listing
    test_paths = [
        '/',
        '/admin/',
        '/backup/',
        '/test/',
        '/.git/',
        '/.svn/',
        '/.env',
        '/wp-admin/',
        '/phpmyadmin/'
    ]
    
    for path in test_paths:
        try:
            response = requests.get(f"{base_url}{path}", timeout=timeout/len(test_paths), verify=False)
            
            # Check for directory listing
            if 'Index of' in response.text or '<title>Directory listing' in response.text:
                result['vulnerabilities'].append({
                    'type': 'directory_listing',
                    'severity': 'medium',
                    'description': f"Directory listing enabled at {path}",
                    'path': path
                })
                
            # Check for sensitive files
            if path in ['/.git/', '/.env'] and response.status_code == 200:
                result['vulnerabilities'].append({
                    'type': 'sensitive_file_exposure',
                    'severity': 'high',
                    'description': f"Sensitive file/directory exposed: {path}",
                    'path': path
                })
                
        except:
            pass
            
    return result


def _check_information_disclosure(base_url: str, timeout: float) -> Dict[str, Any]:
    """Check for information disclosure vulnerabilities."""
    result = {'vulnerabilities': []}
    
    # Check for common information disclosure endpoints
    endpoints = [
        '/server-status',
        '/server-info',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/.DS_Store',
        '/robots.txt',
        '/crossdomain.xml'
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=timeout/len(endpoints), verify=False)
            
            if response.status_code == 200:
                if endpoint in ['/phpinfo.php', '/info.php'] and 'phpinfo()' in response.text:
                    result['vulnerabilities'].append({
                        'type': 'phpinfo_disclosure',
                        'severity': 'high',
                        'description': f"PHP information disclosure at {endpoint}",
                        'endpoint': endpoint
                    })
                elif endpoint == '/server-status' and 'Apache Server Status' in response.text:
                    result['vulnerabilities'].append({
                        'type': 'server_status_exposed',
                        'severity': 'medium',
                        'description': 'Apache server-status page is publicly accessible',
                        'endpoint': endpoint
                    })
                    
        except:
            pass
            
    return result


def _check_http_methods(host: str, port: int, ssl_enabled: bool, timeout: float) -> Dict[str, Any]:
    """Check allowed HTTP methods."""
    result = {'allowed_methods': [], 'dangerous_methods': []}
    
    try:
        # Send OPTIONS request
        if ssl_enabled:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if ssl_enabled:
            sock = context.wrap_socket(sock, server_hostname=host)
            
        sock.connect((host, port))
        
        request = f"OPTIONS / HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
        sock.send(request.encode())
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()
        
        # Parse allowed methods
        for line in response.split('\\r\\n'):
            if line.startswith('Allow:'):
                methods = [m.strip() for m in line.split(':', 1)[1].split(',')]
                result['allowed_methods'] = methods
                
                # Check for dangerous methods
                dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                result['dangerous_methods'] = [m for m in methods if m in dangerous]
                break
                
    except Exception as e:
        logger.error(f"Error checking HTTP methods: {e}")
        
    return result


# Helper functions for SSL scanning

def _check_ssl_certificate(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Check SSL certificate for issues."""
    result = {'certificate': {}, 'issues': []}
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cert_dict = ssl.DER_cert_to_PEM_cert(cert)
                
                # Get certificate info
                peer_cert = ssock.getpeercert()
                if peer_cert:
                    result['certificate'] = {
                        'subject': dict(x[0] for x in peer_cert.get('subject', [])),
                        'issuer': dict(x[0] for x in peer_cert.get('issuer', [])),
                        'version': peer_cert.get('version'),
                        'serial_number': peer_cert.get('serialNumber'),
                        'not_before': peer_cert.get('notBefore'),
                        'not_after': peer_cert.get('notAfter'),
                        'san': peer_cert.get('subjectAltName', [])
                    }
                    
                    # Check expiration
                    from datetime import datetime
                    not_after = datetime.strptime(peer_cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        result['issues'].append({
                            'type': 'expired_certificate',
                            'severity': 'critical',
                            'description': f"Certificate expired on {peer_cert['notAfter']}"
                        })
                    elif not_after < datetime.now() + timedelta(days=30):
                        result['issues'].append({
                            'type': 'expiring_certificate',
                            'severity': 'medium',
                            'description': f"Certificate expiring soon: {peer_cert['notAfter']}"
                        })
                        
                    # Check self-signed
                    if result['certificate']['subject'] == result['certificate']['issuer']:
                        result['issues'].append({
                            'type': 'self_signed_certificate',
                            'severity': 'medium',
                            'description': 'Self-signed certificate detected'
                        })
                        
    except Exception as e:
        logger.error(f"Error checking SSL certificate: {e}")
        
    return result


def _check_ssl_protocols(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Check supported SSL/TLS protocols."""
    result = {'supported': [], 'weak_protocols': []}
    
    protocols = [
        ('SSLv2', ssl.PROTOCOL_SSLv2) if hasattr(ssl, 'PROTOCOL_SSLv2') else None,
        ('SSLv3', ssl.PROTOCOL_SSLv3) if hasattr(ssl, 'PROTOCOL_SSLv3') else None,
        ('TLSv1', ssl.PROTOCOL_TLSv1) if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
        ('TLSv1.1', ssl.PROTOCOL_TLSv1_1) if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
        ('TLSv1.2', ssl.PROTOCOL_TLSv1_2) if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
        ('TLSv1.3', ssl.PROTOCOL_TLS) if hasattr(ssl, 'PROTOCOL_TLS') else None,
    ]
    
    weak_protos = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    for proto_name, proto_const in protocols:
        if proto_const is None:
            continue
            
        try:
            context = ssl.SSLContext(proto_const)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.connect((host, port))
            ssock.close()
            
            result['supported'].append(proto_name)
            if proto_name in weak_protos:
                result['weak_protocols'].append(proto_name)
                
        except:
            pass
            
    return result


def _check_ssl_ciphers(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Check supported cipher suites."""
    result = {'supported': [], 'weak_ciphers': []}
    
    # This is a simplified check - full cipher enumeration would be more complex
    weak_cipher_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    result['supported'].append(cipher[0])
                    
                    # Check if it's a weak cipher
                    for pattern in weak_cipher_patterns:
                        if pattern in cipher[0]:
                            result['weak_ciphers'].append(cipher[0])
                            break
                            
    except Exception as e:
        logger.error(f"Error checking SSL ciphers: {e}")
        
    return result


# Database security scanning helpers

def _scan_mysql_security(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Scan MySQL for security issues."""
    result = {'vulnerabilities': [], 'config_issues': []}
    
    # Check for anonymous access
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # MySQL sends greeting, we can check version
        greeting = sock.recv(1024)
        sock.close()
        
        # Very basic check - in practice would need MySQL protocol implementation
        result['config_issues'].append({
            'type': 'mysql_exposed',
            'description': 'MySQL is accessible from network',
            'recommendation': 'Bind MySQL to localhost only if not needed externally'
        })
        
    except:
        pass
        
    return result


def _scan_postgresql_security(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Scan PostgreSQL for security issues."""
    result = {'vulnerabilities': [], 'config_issues': []}
    
    # Similar basic check
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        
        result['config_issues'].append({
            'type': 'postgresql_exposed',
            'description': 'PostgreSQL is accessible from network',
            'recommendation': 'Review pg_hba.conf for proper access controls'
        })
        
    except:
        pass
        
    return result


def _scan_mongodb_security(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Scan MongoDB for security issues."""
    result = {'vulnerabilities': [], 'config_issues': []}
    
    # Check if MongoDB is accessible without auth
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        
        result['config_issues'].append({
            'type': 'mongodb_exposed',
            'description': 'MongoDB is accessible from network',
            'recommendation': 'Enable authentication and bind to localhost if possible'
        })
        
    except:
        pass
        
    return result


def _scan_redis_security(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Scan Redis for security issues."""
    result = {'vulnerabilities': [], 'config_issues': []}
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try PING command
        sock.send(b"PING\\r\\n")
        response = sock.recv(1024)
        
        if b'+PONG' in response:
            result['vulnerabilities'].append({
                'type': 'redis_no_auth',
                'severity': 'high',
                'description': 'Redis accessible without authentication'
            })
            
        sock.close()
        
    except:
        pass
        
    return result


# SMB scanning helpers

def _check_smb_version(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Basic SMB version check."""
    # This would require SMB protocol implementation
    # Simplified version
    return {
        'version': 'unknown',
        'signing_not_required': False
    }


def _enumerate_smb_shares(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Enumerate SMB shares."""
    # This would require SMB protocol implementation
    # Simplified version
    return {
        'shares': [],
        'anonymous_access': False,
        'anonymous_shares': []
    }


# Credential testing helpers (use with caution!)

def _test_ssh_credentials(host: str, port: int, creds: List[Tuple[str, str]], 
                         timeout: float) -> Dict[str, Any]:
    """Test SSH credentials (requires paramiko)."""
    result = {
        'type': 'default_credentials',
        'service': 'ssh',
        'port': port,
        'vulnerable': False,
        'credentials': []
    }
    
    # This would require paramiko for actual testing
    # Placeholder for safety
    logger.warning("SSH credential testing not implemented for safety")
    
    return result


def _test_ftp_credentials(host: str, port: int, creds: List[Tuple[str, str]], 
                         timeout: float) -> Dict[str, Any]:
    """Test FTP credentials."""
    result = {
        'type': 'default_credentials',
        'service': 'ftp',
        'port': port,
        'vulnerable': False,
        'credentials': []
    }
    
    # Test anonymous access
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Get banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Try anonymous login
        sock.send(b"USER anonymous\\r\\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        if '331' in response:  # Password required
            sock.send(b"PASS anonymous@\\r\\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '230' in response:  # Login successful
                result['vulnerable'] = True
                result['credentials'].append(('anonymous', 'anonymous@'))
                result['severity'] = 'medium'
                result['description'] = 'FTP server allows anonymous access'
                
        sock.close()
        
    except:
        pass
        
    return result