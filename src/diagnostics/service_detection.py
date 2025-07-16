"""
Service Detection Module for Claude Code Orchestration

This module provides modular service detection functions that Claude Code can
invoke to identify services running on network devices. All functions are designed
to be independent and composable.
"""

import socket
import subprocess
import json
import re
import threading
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import concurrent.futures

from ..utils.logger import get_logger

logger = get_logger(__name__)


# Service signatures for banner-based detection
SERVICE_SIGNATURES = {
    'SSH': {
        'patterns': [r'SSH-\d+\.\d+', r'OpenSSH'],
        'default_ports': [22, 2222],
        'banner_prefix': 'SSH-'
    },
    'HTTP': {
        'patterns': [r'HTTP/\d+\.\d+', r'Server:', r'nginx', r'Apache'],
        'default_ports': [80, 8080, 8000],
        'http_methods': ['GET', 'HEAD']
    },
    'HTTPS': {
        'patterns': [r'HTTP/\d+\.\d+'],
        'default_ports': [443, 8443],
        'ssl_required': True
    },
    'FTP': {
        'patterns': [r'220.*FTP', r'vsftpd', r'ProFTPD', r'Pure-FTPd'],
        'default_ports': [21],
        'banner_prefix': '220'
    },
    'SMTP': {
        'patterns': [r'220.*SMTP', r'Postfix', r'Exim', r'sendmail'],
        'default_ports': [25, 587, 465],
        'banner_prefix': '220'
    },
    'POP3': {
        'patterns': [r'\+OK.*POP3', r'Dovecot'],
        'default_ports': [110, 995],
        'banner_prefix': '+OK'
    },
    'IMAP': {
        'patterns': [r'\* OK.*IMAP', r'Dovecot', r'Courier'],
        'default_ports': [143, 993],
        'banner_prefix': '* OK'
    },
    'MySQL': {
        'patterns': [r'mysql', r'MariaDB'],
        'default_ports': [3306],
        'binary_protocol': True
    },
    'PostgreSQL': {
        'patterns': [r'PostgreSQL'],
        'default_ports': [5432],
        'startup_packet': True
    },
    'RDP': {
        'patterns': [],
        'default_ports': [3389],
        'binary_protocol': True
    },
    'SMB': {
        'patterns': [],
        'default_ports': [445, 139],
        'binary_protocol': True
    },
    'DNS': {
        'patterns': [],
        'default_ports': [53],
        'udp_service': True
    },
    'LDAP': {
        'patterns': [],
        'default_ports': [389, 636],
        'binary_protocol': True
    },
    'Telnet': {
        'patterns': [r'telnet', r'login:'],
        'default_ports': [23],
        'banner_prefix': '\xff'
    }
}


def detect_service_banner(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Attempt to grab service banner and identify the service.
    
    Args:
        host: Target hostname or IP address
        port: Port number to probe
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary containing service information
        
    Example:
        >>> result = detect_service_banner('192.168.1.1', 22)
        >>> print(result)
        {'service': 'SSH', 'version': '2.0', 'banner': 'SSH-2.0-OpenSSH_8.9'}
    """
    result = {
        'host': host,
        'port': port,
        'service': 'unknown',
        'version': None,
        'banner': None,
        'error': None,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try to receive banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                result['banner'] = banner
                
                # Identify service from banner
                service_info = _identify_service_from_banner(banner, port)
                result.update(service_info)
            else:
                # No banner received, try sending probe
                probe_result = _send_service_probe(sock, port)
                result.update(probe_result)
                
        except socket.timeout:
            # No banner received, try active probing
            probe_result = _send_service_probe(sock, port)
            result.update(probe_result)
            
        sock.close()
        
    except socket.timeout:
        result['error'] = 'Connection timeout'
    except ConnectionRefused:
        result['error'] = 'Connection refused'
    except Exception as e:
        result['error'] = str(e)
        
    # If still unknown, guess by port
    if result['service'] == 'unknown' and not result['error']:
        result['service'] = _guess_service_by_port(port)
        
    return result


def detect_services_batch(host: str, ports: List[int], timeout: float = 3.0, 
                         max_workers: int = 10) -> List[Dict[str, Any]]:
    """
    Detect services on multiple ports in parallel.
    
    Args:
        host: Target hostname or IP address
        ports: List of ports to probe
        timeout: Connection timeout per port
        max_workers: Maximum concurrent connections
        
    Returns:
        List of service detection results
        
    Example:
        >>> open_ports = [80, 443, 22]
        >>> services = detect_services_batch('192.168.1.1', open_ports)
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_port = {
            executor.submit(detect_service_banner, host, port, timeout): port
            for port in ports
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            results.append(result)
            
    # Sort by port number for consistent output
    results.sort(key=lambda x: x['port'])
    return results


def detect_http_service(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Specialized HTTP/HTTPS service detection with detailed information.
    
    Args:
        host: Target hostname or IP address
        port: Port number to probe
        timeout: Connection timeout
        
    Returns:
        Dictionary with HTTP service details
        
    Example:
        >>> http_info = detect_http_service('example.com', 443)
        >>> print(http_info['server'])
        'nginx/1.18.0'
    """
    result = {
        'host': host,
        'port': port,
        'service': 'HTTP',
        'ssl': port in [443, 8443] or port > 1024,
        'server': None,
        'headers': {},
        'error': None,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        # Construct HTTP request
        if result['ssl']:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.connect((host, port))
            
            # Send HTTP request
            request = f"HEAD / HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
            ssock.send(request.encode())
            response = ssock.recv(4096).decode('utf-8', errors='ignore')
            ssock.close()
            
            result['service'] = 'HTTPS'
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            request = f"HEAD / HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
        # Parse response
        if response:
            lines = response.split('\\r\\n')
            if lines[0].startswith('HTTP/'):
                result['http_version'] = lines[0].split()[0]
                result['status_code'] = lines[0].split()[1] if len(lines[0].split()) > 1 else None
                
                # Parse headers
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        result['headers'][key.lower()] = value
                        
                        # Extract server info
                        if key.lower() == 'server':
                            result['server'] = value
                            
    except Exception as e:
        result['error'] = str(e)
        
    return result


def detect_database_service(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Specialized database service detection (MySQL, PostgreSQL, etc).
    
    Args:
        host: Target hostname or IP address
        port: Port number to probe
        timeout: Connection timeout
        
    Returns:
        Dictionary with database service details
    """
    result = {
        'host': host,
        'port': port,
        'service': 'unknown',
        'database_type': None,
        'version': None,
        'error': None,
        'timestamp': datetime.now().isoformat()
    }
    
    # MySQL detection
    if port in [3306]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # MySQL sends a greeting packet
            greeting = sock.recv(1024)
            if len(greeting) > 4:
                # Parse MySQL greeting
                protocol_version = greeting[0]
                null_pos = greeting[1:].find(b'\\x00')
                if null_pos > 0:
                    version = greeting[1:null_pos+1].decode('utf-8', errors='ignore')
                    result['service'] = 'MySQL'
                    result['database_type'] = 'MySQL'
                    result['version'] = version
                    
            sock.close()
        except Exception as e:
            result['error'] = str(e)
            
    # PostgreSQL detection
    elif port in [5432]:
        result['service'] = 'PostgreSQL'
        result['database_type'] = 'PostgreSQL'
        # PostgreSQL requires startup packet, simplified detection
        
    # MongoDB detection
    elif port in [27017]:
        result['service'] = 'MongoDB'
        result['database_type'] = 'MongoDB'
        
    # Redis detection
    elif port in [6379]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send PING command
            sock.send(b"PING\\r\\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '+PONG' in response:
                result['service'] = 'Redis'
                result['database_type'] = 'Redis'
                
            sock.close()
        except Exception as e:
            result['error'] = str(e)
            
    return result


def scan_well_known_services(host: str, timeout: float = 2.0) -> List[Dict[str, Any]]:
    """
    Scan common service ports to quickly identify running services.
    
    Args:
        host: Target hostname or IP address
        timeout: Connection timeout per port
        
    Returns:
        List of detected services
        
    Example:
        >>> services = scan_well_known_services('192.168.1.1')
        >>> for svc in services:
        ...     print(f"Port {svc['port']}: {svc['service']}")
    """
    # Common ports to check
    common_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        27017  # MongoDB
    ]
    
    # First, check which ports are open
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            open_ports.append(port)
            sock.close()
        except:
            pass
            
    # Then detect services on open ports
    if open_ports:
        return detect_services_batch(host, open_ports, timeout)
    else:
        return []


# Helper functions

def _identify_service_from_banner(banner: str, port: int) -> Dict[str, Any]:
    """Identify service from banner text."""
    result = {'service': 'unknown', 'version': None}
    
    for service, info in SERVICE_SIGNATURES.items():
        for pattern in info.get('patterns', []):
            if re.search(pattern, banner, re.IGNORECASE):
                result['service'] = service
                
                # Try to extract version
                version_match = re.search(r'(\d+\.[\d\.]+)', banner)
                if version_match:
                    result['version'] = version_match.group(1)
                    
                # Special handling for specific services
                if service == 'SSH' and banner.startswith('SSH-'):
                    parts = banner.split('-')
                    if len(parts) >= 3:
                        result['version'] = parts[1]
                        result['software'] = parts[2].split()[0]
                        
                return result
                
    return result


def _send_service_probe(sock: socket.socket, port: int) -> Dict[str, Any]:
    """Send active probe to identify service."""
    result = {'service': 'unknown', 'version': None}
    
    try:
        # HTTP probe
        if port in [80, 8080, 8000]:
            sock.send(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if 'HTTP/' in response:
                result['service'] = 'HTTP'
                result['banner'] = response.split('\\r\\n')[0]
                
        # HTTPS probe (would need SSL handling)
        elif port in [443, 8443]:
            result['service'] = 'HTTPS'
            
        # SMTP probe
        elif port in [25, 587]:
            sock.send(b"EHLO test\\r\\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if '250' in response or '220' in response:
                result['service'] = 'SMTP'
                result['banner'] = response
                
    except:
        pass
        
    return result


def _guess_service_by_port(port: int) -> str:
    """Guess service based on port number."""
    port_service_map = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP',
        8443: 'HTTPS',
        27017: 'MongoDB'
    }
    
    return port_service_map.get(port, 'unknown')


# Integration with python-nmap (if available)

def detect_services_nmap(host: str, ports: str = None, timeout: int = 300) -> Dict[str, Any]:
    """
    Use nmap for comprehensive service detection (if available).
    
    Args:
        host: Target hostname or IP address
        ports: Port specification (e.g., '1-1000', '80,443,22')
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary with nmap scan results
        
    Note:
        This function requires python-nmap to be installed and nmap binary available.
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        
        # Prepare scan arguments
        arguments = '-sV'  # Version detection
        if ports:
            nm.scan(hosts=host, ports=ports, arguments=arguments, timeout=timeout)
        else:
            nm.scan(hosts=host, arguments=arguments, timeout=timeout)
            
        results = {
            'host': host,
            'scan_method': 'nmap',
            'services': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Parse results
        if host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service_info = nm[host][proto][port]
                    results['services'].append({
                        'port': port,
                        'protocol': proto,
                        'state': service_info['state'],
                        'service': service_info.get('name', 'unknown'),
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'extrainfo': service_info.get('extrainfo', ''),
                        'cpe': service_info.get('cpe', '')
                    })
                    
        return results
        
    except ImportError:
        logger.warning("python-nmap not available, using built-in detection")
        # Fall back to built-in detection
        if ports:
            port_list = []
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
            services = detect_services_batch(host, port_list)
        else:
            services = scan_well_known_services(host)
            
        return {
            'host': host,
            'scan_method': 'built-in',
            'services': services,
            'timestamp': datetime.now().isoformat()
        }