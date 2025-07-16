"""
Modular security scanning functions for Claude Code orchestration

This module provides independent, composable security scanning functions
that Claude Code can invoke and combine for customized security assessments.
"""

import socket
import struct
import select
import time
import threading
import ipaddress
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
import concurrent.futures
import subprocess
import json
import re
import platform

from ..utils.logger import get_logger

logger = get_logger(__name__)


# Port scanning functions
def scan_tcp_port(host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Scan a single TCP port on a host using a simple connection attempt.
    
    Args:
        host: Target hostname or IP address
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        dict: Port scan result with status and timing information
        
    Example:
        >>> result = scan_tcp_port('192.168.1.1', 80)
        >>> print(result)
        {'host': '192.168.1.1', 'port': 80, 'state': 'open', 'latency': 0.023}
    """
    start_time = time.time()
    result = {
        'host': host,
        'port': port,
        'state': 'closed',
        'latency': None,
        'error': None,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt connection
        connection_result = sock.connect_ex((host, port))
        
        if connection_result == 0:
            result['state'] = 'open'
            result['latency'] = time.time() - start_time
        else:
            result['state'] = 'closed'
            
        sock.close()
        
    except socket.gaierror as e:
        result['state'] = 'error'
        result['error'] = f'DNS resolution failed: {str(e)}'
    except socket.timeout:
        result['state'] = 'filtered'
        result['error'] = 'Connection timed out'
    except Exception as e:
        result['state'] = 'error'
        result['error'] = str(e)
    
    return result


def scan_tcp_ports_batch(host: str, ports: List[int], 
                        timeout: float = 1.0, 
                        max_workers: int = 50) -> List[Dict[str, Any]]:
    """
    Scan multiple TCP ports in parallel using thread pool.
    
    Args:
        host: Target hostname or IP address
        ports: List of port numbers to scan
        timeout: Connection timeout per port
        max_workers: Maximum concurrent connections
        
    Returns:
        list: Results for all scanned ports
        
    Example:
        >>> results = scan_tcp_ports_batch('192.168.1.1', [80, 443, 22, 3389])
        >>> open_ports = [r for r in results if r['state'] == 'open']
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scans
        future_to_port = {
            executor.submit(scan_tcp_port, host, port, timeout): port 
            for port in ports
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                port = future_to_port[future]
                results.append({
                    'host': host,
                    'port': port,
                    'state': 'error',
                    'error': str(e)
                })
    
    # Sort by port number
    results.sort(key=lambda x: x['port'])
    return results


def scan_tcp_range(host: str, start_port: int = 1, end_port: int = 1024,
                  timeout: float = 1.0, max_workers: int = 50) -> List[Dict[str, Any]]:
    """
    Scan a range of TCP ports on a host.
    
    Args:
        host: Target hostname or IP address
        start_port: First port in range
        end_port: Last port in range (inclusive)
        timeout: Connection timeout per port
        max_workers: Maximum concurrent connections
        
    Returns:
        list: Results for all scanned ports
    """
    ports = list(range(start_port, end_port + 1))
    return scan_tcp_ports_batch(host, ports, timeout, max_workers)


def scan_common_ports(host: str, service_type: str = 'all',
                     timeout: float = 1.0) -> List[Dict[str, Any]]:
    """
    Scan commonly used ports based on service type.
    
    Args:
        host: Target hostname or IP address
        service_type: Type of services to scan for ('web', 'database', 'remote', 'mail', 'all')
        timeout: Connection timeout per port
        
    Returns:
        list: Results for scanned ports with service annotations
    """
    common_ports = {
        'web': {
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            3000: 'Node.js',
            5000: 'Flask',
            8000: 'Django'
        },
        'database': {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'SQL Server',
            1521: 'Oracle',
            27017: 'MongoDB',
            6379: 'Redis',
            9042: 'Cassandra'
        },
        'remote': {
            22: 'SSH',
            23: 'Telnet',
            3389: 'RDP',
            5900: 'VNC',
            5985: 'WinRM-HTTP',
            5986: 'WinRM-HTTPS'
        },
        'mail': {
            25: 'SMTP',
            465: 'SMTPS',
            587: 'SMTP-TLS',
            110: 'POP3',
            995: 'POP3S',
            143: 'IMAP',
            993: 'IMAPS'
        }
    }
    
    # Determine which ports to scan
    if service_type == 'all':
        ports_to_scan = {}
        for category in common_ports.values():
            ports_to_scan.update(category)
    else:
        ports_to_scan = common_ports.get(service_type, {})
    
    # Scan the ports
    results = scan_tcp_ports_batch(host, list(ports_to_scan.keys()), timeout)
    
    # Annotate with service names
    for result in results:
        port = result['port']
        if port in ports_to_scan:
            result['service'] = ports_to_scan[port]
            result['category'] = service_type if service_type != 'all' else _get_port_category(port, common_ports)
    
    return results


def _get_port_category(port: int, port_categories: Dict[str, Dict[int, str]]) -> str:
    """Get the category for a given port."""
    for category, ports in port_categories.items():
        if port in ports:
            return category
    return 'unknown'


# Service detection functions
def detect_service_banner(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Attempt to grab service banner from an open port.
    
    Args:
        host: Target hostname or IP address
        port: Port number to probe
        timeout: Connection timeout in seconds
        
    Returns:
        dict: Service detection results including banner if found
    """
    result = {
        'host': host,
        'port': port,
        'banner': None,
        'service': None,
        'version': None,
        'error': None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Some services send banner immediately
        sock.settimeout(1.0)
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                result['banner'] = banner
                result.update(_parse_banner(banner))
        except socket.timeout:
            # Try sending a probe
            probes = _get_service_probes(port)
            for probe_name, probe_data in probes.items():
                try:
                    sock.send(probe_data.encode())
                    response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if response:
                        result['banner'] = response
                        result['probe'] = probe_name
                        result.update(_parse_banner(response))
                        break
                except:
                    continue
        
        sock.close()
        
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def _get_service_probes(port: int) -> Dict[str, str]:
    """Get service-specific probes based on port."""
    probes = {
        80: {'HTTP': "GET / HTTP/1.0\r\n\r\n"},
        443: {'HTTPS': "GET / HTTP/1.0\r\n\r\n"},
        21: {'FTP': "HELP\r\n"},
        22: {'SSH': "SSH-2.0-Probe\r\n"},
        25: {'SMTP': "EHLO probe\r\n"},
        110: {'POP3': "QUIT\r\n"},
        143: {'IMAP': "a001 CAPABILITY\r\n"}
    }
    
    return probes.get(port, {'Generic': "\r\n"})


def _parse_banner(banner: str) -> Dict[str, Any]:
    """Parse banner to extract service and version information."""
    parsed = {}
    
    # Common patterns
    patterns = {
        'SSH': r'SSH-(\d+\.\d+)-(.+)',
        'HTTP': r'Server:\s*([^\r\n]+)',
        'FTP': r'220[- ](.+?)(?:\r|\n|$)',
        'SMTP': r'220[- ](.+?)(?:\r|\n|$)',
        'MySQL': r'(\d+\.\d+\.\d+)',
        'PostgreSQL': r'PostgreSQL (\d+\.\d+)',
        'Redis': r'Redis (\d+\.\d+\.\d+)'
    }
    
    for service, pattern in patterns.items():
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            parsed['service'] = service
            if service == 'SSH':
                parsed['version'] = match.group(1)
                parsed['software'] = match.group(2)
            else:
                parsed['version'] = match.group(1) if match.groups() else None
            break
    
    return parsed


def detect_services_batch(host: str, ports: List[int], 
                         timeout: float = 3.0,
                         max_workers: int = 10) -> List[Dict[str, Any]]:
    """
    Detect services on multiple ports in parallel.
    
    Args:
        host: Target hostname or IP address
        ports: List of port numbers to probe
        timeout: Connection timeout per port
        max_workers: Maximum concurrent connections
        
    Returns:
        list: Service detection results for all ports
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(detect_service_banner, host, port, timeout): port 
            for port in ports
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                port = future_to_port[future]
                results.append({
                    'host': host,
                    'port': port,
                    'error': str(e)
                })
    
    results.sort(key=lambda x: x['port'])
    return results


# Vulnerability checking functions
def check_weak_services(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Check scan results for potentially vulnerable services.
    
    Args:
        scan_results: List of port scan results
        
    Returns:
        list: Identified vulnerabilities and recommendations
    """
    vulnerabilities = []
    
    weak_services = {
        21: {'name': 'FTP', 'risk': 'high', 'issue': 'Unencrypted authentication and data transfer'},
        23: {'name': 'Telnet', 'risk': 'critical', 'issue': 'Unencrypted remote access'},
        69: {'name': 'TFTP', 'risk': 'high', 'issue': 'No authentication, cleartext transfer'},
        135: {'name': 'RPC', 'risk': 'high', 'issue': 'Remote procedure call exposure'},
        139: {'name': 'NetBIOS', 'risk': 'high', 'issue': 'Legacy protocol, information disclosure'},
        445: {'name': 'SMB', 'risk': 'high', 'issue': 'File sharing exposure, ransomware vector'},
        512: {'name': 'rexec', 'risk': 'critical', 'issue': 'Remote execution service'},
        513: {'name': 'rlogin', 'risk': 'critical', 'issue': 'Unencrypted remote login'},
        514: {'name': 'rsh', 'risk': 'critical', 'issue': 'Unencrypted remote shell'},
        1433: {'name': 'SQL Server', 'risk': 'medium', 'issue': 'Database exposed to network'},
        3306: {'name': 'MySQL', 'risk': 'medium', 'issue': 'Database exposed to network'},
        5432: {'name': 'PostgreSQL', 'risk': 'medium', 'issue': 'Database exposed to network'},
        5900: {'name': 'VNC', 'risk': 'high', 'issue': 'Remote desktop often weakly secured'},
        6379: {'name': 'Redis', 'risk': 'high', 'issue': 'Often deployed without authentication'},
        27017: {'name': 'MongoDB', 'risk': 'high', 'issue': 'Often deployed without authentication'}
    }
    
    for result in scan_results:
        if result.get('state') == 'open' and result.get('port') in weak_services:
            port = result['port']
            service_info = weak_services[port]
            
            vulnerability = {
                'type': 'weak_service',
                'host': result['host'],
                'port': port,
                'service': service_info['name'],
                'risk_level': service_info['risk'],
                'issue': service_info['issue'],
                'recommendation': _get_service_recommendation(port, service_info['name'])
            }
            
            vulnerabilities.append(vulnerability)
    
    return vulnerabilities


def _get_service_recommendation(port: int, service: str) -> str:
    """Get security recommendation for a service."""
    recommendations = {
        21: "Replace FTP with SFTP or FTPS for encrypted file transfers",
        23: "Disable Telnet immediately and use SSH for remote access",
        69: "Disable TFTP unless absolutely necessary, use SCP/SFTP instead",
        135: "Block RPC ports at firewall, restrict to trusted networks only",
        139: "Disable NetBIOS over TCP/IP if not required",
        445: "Restrict SMB access to trusted networks, enable SMB signing",
        512: "Disable rexec service, use SSH for remote execution",
        513: "Disable rlogin service, use SSH for remote access",
        514: "Disable rsh service, use SSH for remote shell access",
        1433: "Restrict SQL Server access to application servers only",
        3306: "Restrict MySQL access to application servers only",
        5432: "Restrict PostgreSQL access to application servers only",
        5900: "Use VPN for VNC access, enable encryption and strong passwords",
        6379: "Enable Redis authentication and bind to localhost only",
        27017: "Enable MongoDB authentication and restrict network access"
    }
    
    return recommendations.get(port, f"Review security configuration for {service}")


def check_ssl_certificate(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Check SSL/TLS certificate on a service.
    
    Args:
        host: Target hostname or IP address
        port: Port number (default 443)
        timeout: Connection timeout
        
    Returns:
        dict: Certificate validation results
    """
    import ssl
    import certifi
    from datetime import datetime
    
    result = {
        'host': host,
        'port': port,
        'valid': False,
        'issues': [],
        'certificate': None,
        'error': None
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context(cafile=certifi.where())
        
        # Connect and get certificate
        with socket.create_connection((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                result['certificate'] = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])]
                }
                
                # Check expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.now():
                    result['issues'].append({
                        'type': 'expired',
                        'severity': 'critical',
                        'message': f'Certificate expired on {not_after}'
                    })
                elif (not_after - datetime.now()).days < 30:
                    result['issues'].append({
                        'type': 'expiring_soon',
                        'severity': 'warning',
                        'message': f'Certificate expires in {(not_after - datetime.now()).days} days'
                    })
                
                # Check hostname match
                ssl.match_hostname(cert, host)
                
                result['valid'] = len(result['issues']) == 0
                
    except ssl.SSLError as e:
        result['error'] = f'SSL Error: {str(e)}'
        result['issues'].append({
            'type': 'ssl_error',
            'severity': 'critical',
            'message': str(e)
        })
    except ssl.CertificateError as e:
        result['error'] = f'Certificate Error: {str(e)}'
        result['issues'].append({
            'type': 'hostname_mismatch',
            'severity': 'critical',
            'message': str(e)
        })
    except Exception as e:
        result['error'] = str(e)
    
    return result


# CVE lookup functions (simplified - would integrate with real CVE database)
def search_cves_for_service(service: str, version: str = None) -> List[Dict[str, Any]]:
    """
    Search for known CVEs for a service and version.
    
    Args:
        service: Service name (e.g., 'Apache', 'nginx', 'OpenSSH')
        version: Service version (optional)
        
    Returns:
        list: Matching CVE records
    """
    # This is a simplified implementation
    # In production, would query NVD API or local CVE database
    
    known_vulnerabilities = {
        'SSH': {
            '7.0': [
                {
                    'cve_id': 'CVE-2016-10009',
                    'severity': 'high',
                    'cvss_score': 7.3,
                    'description': 'Remote code execution vulnerability'
                }
            ]
        },
        'Apache': {
            '2.4.49': [
                {
                    'cve_id': 'CVE-2021-41773',
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'description': 'Path traversal and RCE vulnerability'
                }
            ]
        }
    }
    
    cves = []
    if service in known_vulnerabilities:
        if version and version in known_vulnerabilities[service]:
            cves = known_vulnerabilities[service][version]
        else:
            # Return all CVEs for the service if no version match
            for v, vuln_list in known_vulnerabilities[service].items():
                cves.extend(vuln_list)
    
    return cves


# Orchestration helper functions
def perform_security_scan(target: str, scan_type: str = 'basic', 
                         options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Perform a complete security scan based on scan type.
    
    This is a high-level function that Claude Code can call to orchestrate
    various security scanning functions based on the requested scan type.
    
    Args:
        target: Target hostname or IP address
        scan_type: Type of scan ('basic', 'full', 'web', 'quick')
        options: Additional options for customization
        
    Returns:
        dict: Complete scan results with all findings
    """
    options = options or {}
    results = {
        'target': target,
        'scan_type': scan_type,
        'start_time': datetime.now().isoformat(),
        'port_scan': [],
        'services': [],
        'vulnerabilities': [],
        'ssl_checks': [],
        'recommendations': []
    }
    
    try:
        # Determine ports to scan based on scan type
        if scan_type == 'quick':
            # Quick scan - top 20 ports
            ports = [21, 22, 23, 25, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        elif scan_type == 'web':
            # Web-focused scan
            ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
        elif scan_type == 'full':
            # Full scan - common 1000 ports
            ports = list(range(1, 1001))
        else:  # basic
            # Basic scan - common services
            results['port_scan'] = scan_common_ports(target, 'all')
            ports = [r['port'] for r in results['port_scan'] if r['state'] == 'open']
        
        # Perform port scan if not already done
        if not results['port_scan']:
            results['port_scan'] = scan_tcp_ports_batch(target, ports)
        
        # Get open ports
        open_ports = [r['port'] for r in results['port_scan'] if r['state'] == 'open']
        
        # Service detection on open ports
        if open_ports:
            results['services'] = detect_services_batch(target, open_ports)
            
            # Check for weak services
            results['vulnerabilities'].extend(check_weak_services(results['port_scan']))
            
            # SSL checks for HTTPS ports
            ssl_ports = [p for p in open_ports if p in [443, 8443, 995, 993, 465, 990]]
            for port in ssl_ports:
                ssl_result = check_ssl_certificate(target, port)
                results['ssl_checks'].append(ssl_result)
                
                # Add SSL issues to vulnerabilities
                if ssl_result.get('issues'):
                    for issue in ssl_result['issues']:
                        results['vulnerabilities'].append({
                            'type': 'ssl_issue',
                            'host': target,
                            'port': port,
                            'issue': issue['message'],
                            'severity': issue['severity']
                        })
        
        # Generate recommendations
        results['recommendations'] = _generate_recommendations(results)
        
        results['end_time'] = datetime.now().isoformat()
        results['status'] = 'completed'
        
    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)
        logger.error(f"Security scan failed: {str(e)}")
    
    return results


def _generate_recommendations(scan_results: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on scan results."""
    recommendations = []
    
    # Check for critical vulnerabilities
    critical_vulns = [v for v in scan_results['vulnerabilities'] 
                     if v.get('risk_level') == 'critical' or v.get('severity') == 'critical']
    if critical_vulns:
        recommendations.append(f"CRITICAL: Address {len(critical_vulns)} critical vulnerabilities immediately")
    
    # Check for exposed databases
    db_ports = [3306, 5432, 1433, 27017, 6379]
    exposed_dbs = [r for r in scan_results['port_scan'] 
                   if r['state'] == 'open' and r['port'] in db_ports]
    if exposed_dbs:
        recommendations.append("Restrict database access to application servers only")
    
    # Check for unencrypted services
    unencrypted = [v for v in scan_results['vulnerabilities'] 
                   if 'unencrypted' in v.get('issue', '').lower()]
    if unencrypted:
        recommendations.append("Replace unencrypted services with secure alternatives")
    
    # SSL recommendations
    ssl_issues = [s for s in scan_results['ssl_checks'] if s.get('issues')]
    if ssl_issues:
        recommendations.append("Address SSL/TLS certificate issues")
    
    # General recommendations
    if not recommendations:
        recommendations.append("Continue regular security assessments")
        recommendations.append("Implement network segmentation for sensitive services")
    
    return recommendations


# Integration with existing security assessment
def enhance_security_assessment(existing_assessment: Dict[str, Any], 
                              target: str,
                              deep_scan: bool = False) -> Dict[str, Any]:
    """
    Enhance existing security assessment with real vulnerability data.
    
    This function can be called by the existing SecurityAssessment class
    to add real scanning capabilities to the assessment.
    
    Args:
        existing_assessment: Current assessment data
        target: Target to scan
        deep_scan: Whether to perform deep scanning
        
    Returns:
        dict: Enhanced assessment with real vulnerability data
    """
    # Perform real security scan
    scan_type = 'full' if deep_scan else 'basic'
    scan_results = perform_security_scan(target, scan_type)
    
    # Merge with existing assessment
    if 'vulnerabilities' in existing_assessment:
        existing_assessment['vulnerabilities']['scan_performed'] = True
        existing_assessment['vulnerabilities']['real_findings'] = scan_results['vulnerabilities']
        existing_assessment['vulnerabilities']['open_ports'] = [
            r for r in scan_results['port_scan'] if r['state'] == 'open'
        ]
        existing_assessment['vulnerabilities']['services_detected'] = scan_results['services']
    
    # Update security issues
    if 'network_security' in existing_assessment:
        real_issues = []
        for vuln in scan_results['vulnerabilities']:
            real_issues.append({
                'type': vuln.get('type', 'vulnerability'),
                'severity': vuln.get('risk_level', vuln.get('severity', 'medium')),
                'port': vuln.get('port'),
                'service': vuln.get('service'),
                'message': vuln.get('issue', vuln.get('message', 'Security issue detected'))
            })
        existing_assessment['network_security']['security_issues'].extend(real_issues)
    
    return existing_assessment