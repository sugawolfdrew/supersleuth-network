#!/usr/bin/env python3
"""
Port Connectivity Scanner Module
Advanced port scanning and service availability diagnostics for SuperSleuth Network

This module provides comprehensive port scanning capabilities that Claude Code
can use to diagnose connectivity issues. It uses only Python standard library
(socket module) for maximum portability.
"""

import socket
import time
import threading
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime
import json
import struct
import errno

from ..utils.logger import get_logger
from ..core.diagnostic import BaseDiagnostic, DiagnosticResult
from ..core.authorization import AuthorizationRequest, RiskLevel


# Common service port definitions
COMMON_SERVICES = {
    # Web Services
    80: {'name': 'HTTP', 'protocol': 'tcp', 'category': 'web'},
    443: {'name': 'HTTPS', 'protocol': 'tcp', 'category': 'web'},
    8080: {'name': 'HTTP-ALT', 'protocol': 'tcp', 'category': 'web'},
    8443: {'name': 'HTTPS-ALT', 'protocol': 'tcp', 'category': 'web'},
    
    # Email Services
    25: {'name': 'SMTP', 'protocol': 'tcp', 'category': 'email'},
    587: {'name': 'SMTP-TLS', 'protocol': 'tcp', 'category': 'email'},
    465: {'name': 'SMTPS', 'protocol': 'tcp', 'category': 'email'},
    110: {'name': 'POP3', 'protocol': 'tcp', 'category': 'email'},
    995: {'name': 'POP3S', 'protocol': 'tcp', 'category': 'email'},
    143: {'name': 'IMAP', 'protocol': 'tcp', 'category': 'email'},
    993: {'name': 'IMAPS', 'protocol': 'tcp', 'category': 'email'},
    
    # Database Services
    3306: {'name': 'MySQL', 'protocol': 'tcp', 'category': 'database'},
    5432: {'name': 'PostgreSQL', 'protocol': 'tcp', 'category': 'database'},
    1433: {'name': 'MSSQL', 'protocol': 'tcp', 'category': 'database'},
    1521: {'name': 'Oracle', 'protocol': 'tcp', 'category': 'database'},
    27017: {'name': 'MongoDB', 'protocol': 'tcp', 'category': 'database'},
    6379: {'name': 'Redis', 'protocol': 'tcp', 'category': 'database'},
    9200: {'name': 'Elasticsearch', 'protocol': 'tcp', 'category': 'database'},
    
    # File Services
    21: {'name': 'FTP', 'protocol': 'tcp', 'category': 'file'},
    22: {'name': 'SSH', 'protocol': 'tcp', 'category': 'file'},
    23: {'name': 'Telnet', 'protocol': 'tcp', 'category': 'file'},
    445: {'name': 'SMB', 'protocol': 'tcp', 'category': 'file'},
    139: {'name': 'NetBIOS', 'protocol': 'tcp', 'category': 'file'},
    
    # DNS and Network Services
    53: {'name': 'DNS', 'protocol': 'udp', 'category': 'network'},
    67: {'name': 'DHCP-Server', 'protocol': 'udp', 'category': 'network'},
    68: {'name': 'DHCP-Client', 'protocol': 'udp', 'category': 'network'},
    123: {'name': 'NTP', 'protocol': 'udp', 'category': 'network'},
    161: {'name': 'SNMP', 'protocol': 'udp', 'category': 'network'},
    
    # Remote Access
    3389: {'name': 'RDP', 'protocol': 'tcp', 'category': 'remote'},
    5900: {'name': 'VNC', 'protocol': 'tcp', 'category': 'remote'},
    
    # Other Common Services
    8000: {'name': 'HTTP-DEV', 'protocol': 'tcp', 'category': 'web'},
    9000: {'name': 'PHP-FPM', 'protocol': 'tcp', 'category': 'web'},
    5000: {'name': 'Flask', 'protocol': 'tcp', 'category': 'web'},
    3000: {'name': 'Node.js', 'protocol': 'tcp', 'category': 'web'},
}


def check_single_port(host: str, port: int, timeout: float = 2.0, 
                     protocol: str = 'tcp') -> Dict[str, Any]:
    """
    Check connectivity to a single port on a host
    
    Args:
        host: Target hostname or IP address
        port: Port number to check
        timeout: Connection timeout in seconds
        protocol: Protocol to use ('tcp' or 'udp')
    
    Returns:
        Dictionary with connection results including:
        - open: Boolean indicating if port is open
        - latency: Connection latency in milliseconds
        - service: Service name if known
        - error: Error message if connection failed
    """
    result = {
        'host': host,
        'port': port,
        'protocol': protocol,
        'open': False,
        'latency': None,
        'service': COMMON_SERVICES.get(port, {}).get('name', 'Unknown'),
        'category': COMMON_SERVICES.get(port, {}).get('category', 'other'),
        'error': None,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        start_time = time.time()
        
        if protocol == 'tcp':
            # TCP connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Attempt connection
            result_code = sock.connect_ex((host, port))
            
            if result_code == 0:
                result['open'] = True
                result['latency'] = round((time.time() - start_time) * 1000, 2)
            else:
                result['error'] = f"Connection failed: {errno.errorcode.get(result_code, result_code)}"
            
            sock.close()
            
        elif protocol == 'udp':
            # UDP is connectionless, so we try to send/receive
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send empty packet
            sock.sendto(b'', (host, port))
            
            # Try to receive response (might not get one)
            try:
                data, addr = sock.recvfrom(1024)
                result['open'] = True
                result['latency'] = round((time.time() - start_time) * 1000, 2)
            except socket.timeout:
                # No response doesn't necessarily mean closed for UDP
                result['open'] = None  # Unknown
                result['error'] = "No UDP response (port may still be open)"
            
            sock.close()
            
    except socket.gaierror as e:
        result['error'] = f"DNS resolution failed: {str(e)}"
    except socket.timeout:
        result['error'] = "Connection timed out"
    except Exception as e:
        result['error'] = f"Connection error: {str(e)}"
    
    return result


def scan_port_range(host: str, start_port: int, end_port: int, 
                   timeout: float = 1.0, max_workers: int = 50) -> List[Dict[str, Any]]:
    """
    Scan a range of ports on a host
    
    Args:
        host: Target hostname or IP address
        start_port: Starting port number
        end_port: Ending port number (inclusive)
        timeout: Connection timeout per port
        max_workers: Maximum number of concurrent threads
    
    Returns:
        List of port scan results
    """
    results = []
    
    def scan_port(port):
        # Determine protocol based on service definition
        protocol = COMMON_SERVICES.get(port, {}).get('protocol', 'tcp')
        return check_single_port(host, port, timeout, protocol)
    
    # Use thread pool for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scans
        future_to_port = {
            executor.submit(scan_port, port): port 
            for port in range(start_port, end_port + 1)
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result['open'] or result['open'] is None:  # Include open and unknown UDP
                results.append(result)
    
    return sorted(results, key=lambda x: x['port'])


def scan_common_services(host: str, categories: List[str] = None, 
                        timeout: float = 2.0) -> Dict[str, List[Dict[str, Any]]]:
    """
    Scan common service ports organized by category
    
    Args:
        host: Target hostname or IP address
        categories: List of categories to scan (web, email, database, etc.)
                   If None, scan all categories
        timeout: Connection timeout per port
    
    Returns:
        Dictionary with results organized by service category
    """
    if categories is None:
        categories = ['web', 'email', 'database', 'file', 'network', 'remote']
    
    results = {}
    
    for category in categories:
        results[category] = []
        
        # Get ports for this category
        ports_to_scan = [
            port for port, info in COMMON_SERVICES.items()
            if info['category'] == category
        ]
        
        # Scan each port
        for port in ports_to_scan:
            protocol = COMMON_SERVICES[port]['protocol']
            result = check_single_port(host, port, timeout, protocol)
            results[category].append(result)
    
    return results


def bulk_host_scan(hosts: List[str], ports: List[int], 
                  timeout: float = 2.0, max_workers: int = 20) -> Dict[str, List[Dict[str, Any]]]:
    """
    Scan multiple hosts for specific ports
    
    Args:
        hosts: List of hostnames or IP addresses
        ports: List of ports to check on each host
        timeout: Connection timeout per port
        max_workers: Maximum number of concurrent threads
    
    Returns:
        Dictionary mapping each host to its scan results
    """
    results = {}
    
    def scan_host_port(host_port_tuple):
        host, port = host_port_tuple
        protocol = COMMON_SERVICES.get(port, {}).get('protocol', 'tcp')
        return host, check_single_port(host, port, timeout, protocol)
    
    # Create all host:port combinations
    host_port_pairs = [(host, port) for host in hosts for port in ports]
    
    # Use thread pool for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scans
        future_to_pair = {
            executor.submit(scan_host_port, pair): pair 
            for pair in host_port_pairs
        }
        
        # Collect results
        for future in concurrent.futures.as_completed(future_to_pair):
            host, result = future.result()
            if host not in results:
                results[host] = []
            results[host].append(result)
    
    # Sort results by port for each host
    for host in results:
        results[host] = sorted(results[host], key=lambda x: x['port'])
    
    return results


def test_service_chain(services: List[Dict[str, Any]], 
                      stop_on_failure: bool = True) -> Dict[str, Any]:
    """
    Test a chain of services (useful for multi-tier applications)
    
    Args:
        services: List of service definitions, each containing:
                 - host: Hostname or IP
                 - port: Port number
                 - name: Service name
                 - timeout: Optional timeout (default 2.0)
        stop_on_failure: Stop testing if a service fails
    
    Returns:
        Dictionary with overall status and individual service results
    """
    results = {
        'overall_status': 'healthy',
        'services': [],
        'failed_services': [],
        'total_latency': 0,
        'timestamp': datetime.now().isoformat()
    }
    
    for service in services:
        host = service['host']
        port = service['port']
        name = service.get('name', f"{host}:{port}")
        timeout = service.get('timeout', 2.0)
        
        # Test the service
        result = check_single_port(host, port, timeout)
        result['name'] = name
        
        results['services'].append(result)
        
        if result['open']:
            if result['latency']:
                results['total_latency'] += result['latency']
        else:
            results['failed_services'].append(name)
            results['overall_status'] = 'degraded'
            
            if stop_on_failure:
                results['overall_status'] = 'failed'
                break
    
    if len(results['failed_services']) == len(services):
        results['overall_status'] = 'failed'
    
    return results


def measure_connection_stability(host: str, port: int, 
                               duration: int = 10, interval: float = 1.0) -> Dict[str, Any]:
    """
    Measure connection stability over time
    
    Args:
        host: Target hostname or IP address
        port: Port number to test
        duration: Test duration in seconds
        interval: Time between tests in seconds
    
    Returns:
        Dictionary with stability metrics
    """
    results = {
        'host': host,
        'port': port,
        'duration': duration,
        'measurements': [],
        'successful_connections': 0,
        'failed_connections': 0,
        'average_latency': 0,
        'min_latency': float('inf'),
        'max_latency': 0,
        'stability_score': 0,
        'timestamp': datetime.now().isoformat()
    }
    
    start_time = time.time()
    latencies = []
    
    while time.time() - start_time < duration:
        measurement = check_single_port(host, port, timeout=2.0)
        results['measurements'].append(measurement)
        
        if measurement['open']:
            results['successful_connections'] += 1
            if measurement['latency']:
                latencies.append(measurement['latency'])
                results['min_latency'] = min(results['min_latency'], measurement['latency'])
                results['max_latency'] = max(results['max_latency'], measurement['latency'])
        else:
            results['failed_connections'] += 1
        
        time.sleep(interval)
    
    # Calculate statistics
    total_tests = results['successful_connections'] + results['failed_connections']
    if total_tests > 0:
        results['stability_score'] = round(
            (results['successful_connections'] / total_tests) * 100, 2
        )
    
    if latencies:
        results['average_latency'] = round(sum(latencies) / len(latencies), 2)
        results['latency_variance'] = round(
            sum((x - results['average_latency']) ** 2 for x in latencies) / len(latencies), 2
        )
    
    return results


class PortScanner(BaseDiagnostic):
    """
    Port Connectivity Scanner diagnostic
    
    Provides comprehensive port scanning and service availability testing
    for SuperSleuth Network toolkit.
    """
    
    def __init__(self, config: Dict = None):
        if config is None:
            config = {'client_name': 'Local Test'}
        super().__init__(config)
        self.name = "Port Connectivity Scanner"
        self.description = "Advanced port scanning and service availability diagnostics"
    
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        # Only uses standard library, always available
        return True
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'network_connectivity_test',
            'risk_level': 'medium',
            'description': 'Port scanning and service availability testing'
        }
    
    def execute_diagnostic(self) -> DiagnosticResult:
        """Execute port scanning diagnostic"""
        result = DiagnosticResult(self.name)
        
        try:
            # Get target from config or use localhost
            target = self.config.get('target', 'localhost')
            scan_type = self.config.get('scan_type', 'common')
            
            self.logger.info(f"Starting port scan of {target} (type: {scan_type})")
            
            if scan_type == 'common':
                # Scan common services
                scan_results = scan_common_services(target)
                
            elif scan_type == 'range':
                # Scan port range
                start_port = self.config.get('start_port', 1)
                end_port = self.config.get('end_port', 1024)
                scan_results = scan_port_range(target, start_port, end_port)
                
            elif scan_type == 'specific':
                # Scan specific ports
                ports = self.config.get('ports', [80, 443])
                scan_results = bulk_host_scan([target], ports)
                
            elif scan_type == 'stability':
                # Test connection stability
                port = self.config.get('port', 80)
                duration = self.config.get('duration', 10)
                scan_results = measure_connection_stability(target, port, duration)
                
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")
            
            # Process results
            self._analyze_results(result, scan_results)
            
            result.complete({
                'target': target,
                'scan_type': scan_type,
                'scan_results': scan_results
            })
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}")
            result.fail(str(e))
        
        return result
    
    def _analyze_results(self, result: DiagnosticResult, scan_results: Any):
        """Analyze scan results and add findings"""
        if isinstance(scan_results, dict):
            if 'stability_score' in scan_results:
                # Stability test results
                if scan_results['stability_score'] < 95:
                    result.add_warning(
                        f"Connection stability is {scan_results['stability_score']}% "
                        f"({scan_results['failed_connections']} failures)"
                    )
                    result.add_recommendation(
                        "Investigate network reliability issues or service health"
                    )
                
                if scan_results.get('average_latency', 0) > 100:
                    result.add_warning(
                        f"High average latency: {scan_results['average_latency']}ms"
                    )
                    result.add_recommendation(
                        "Check network congestion or consider closer endpoints"
                    )
            
            elif 'web' in scan_results:
                # Common services scan results
                for category, services in scan_results.items():
                    open_services = [s for s in services if s['open']]
                    if open_services:
                        self.logger.info(
                            f"Found {len(open_services)} open {category} services"
                        )
                    
                    # Check for common issues
                    if category == 'web':
                        http_open = any(s['port'] == 80 and s['open'] for s in services)
                        https_open = any(s['port'] == 443 and s['open'] for s in services)
                        
                        if http_open and not https_open:
                            result.add_warning("HTTP is open but HTTPS is not")
                            result.add_recommendation(
                                "Consider enabling HTTPS for secure communication"
                            )
                    
                    elif category == 'email':
                        smtp_tls = any(s['port'] == 587 and s['open'] for s in services)
                        smtp_plain = any(s['port'] == 25 and s['open'] for s in services)
                        
                        if smtp_plain and not smtp_tls:
                            result.add_warning("SMTP without TLS is available")
                            result.add_recommendation(
                                "Use SMTP with TLS (port 587) for secure email"
                            )
        
        elif isinstance(scan_results, list):
            # Port range scan results
            open_ports = [r for r in scan_results if r['open']]
            if len(open_ports) > 50:
                result.add_warning(f"Large number of open ports: {len(open_ports)}")
                result.add_recommendation(
                    "Review firewall rules to minimize attack surface"
                )


# Convenience functions for Claude Code orchestration

def diagnose_website_down(url: str) -> Dict[str, Any]:
    """
    Diagnose why a website might be down
    
    Args:
        url: Website URL (will extract hostname)
    
    Returns:
        Diagnostic results with recommendations
    """
    # Extract hostname from URL
    if url.startswith('http://') or url.startswith('https://'):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        use_https = parsed.scheme == 'https'
    else:
        host = url
        use_https = True
    
    results = {
        'url': url,
        'host': host,
        'diagnosis': [],
        'recommendations': []
    }
    
    # Test HTTP/HTTPS
    http_result = check_single_port(host, 80)
    https_result = check_single_port(host, 443)
    
    results['http'] = http_result
    results['https'] = https_result
    
    if not http_result['open'] and not https_result['open']:
        results['diagnosis'].append("Both HTTP and HTTPS ports are closed")
        results['recommendations'].extend([
            "Check if the web server is running",
            "Verify firewall rules allow web traffic",
            "Check DNS resolution for the hostname"
        ])
    elif use_https and not https_result['open']:
        results['diagnosis'].append("HTTPS port is closed but HTTP is open")
        results['recommendations'].extend([
            "Try accessing the site via HTTP",
            "Check SSL/TLS certificate configuration",
            "Verify HTTPS listener is configured"
        ])
    elif http_result['open'] or https_result['open']:
        results['diagnosis'].append("Web ports are open")
        results['recommendations'].extend([
            "Issue may be with the web application itself",
            "Check web server logs for errors",
            "Verify application is properly deployed"
        ])
    
    # Test common CDN/proxy ports
    cdn_result = check_single_port(host, 8080)
    if cdn_result['open']:
        results['cdn_proxy'] = cdn_result
        results['recommendations'].append(
            "Alternative web service found on port 8080"
        )
    
    return results


def diagnose_email_issues(mail_server: str, email_type: str = 'both') -> Dict[str, Any]:
    """
    Diagnose email connectivity issues
    
    Args:
        mail_server: Mail server hostname
        email_type: 'smtp', 'imap', 'pop3', or 'both'
    
    Returns:
        Diagnostic results for email services
    """
    results = {
        'mail_server': mail_server,
        'diagnosis': [],
        'recommendations': [],
        'services': {}
    }
    
    if email_type in ['smtp', 'both']:
        # Test SMTP ports
        smtp_ports = {
            25: 'SMTP',
            587: 'SMTP-TLS (recommended)',
            465: 'SMTPS (legacy SSL)'
        }
        
        for port, desc in smtp_ports.items():
            result = check_single_port(mail_server, port)
            results['services'][desc] = result
            
            if port == 587 and result['open']:
                results['diagnosis'].append("SMTP with TLS is available (recommended)")
            elif port == 25 and result['open']:
                results['diagnosis'].append("Plain SMTP is available (not recommended)")
    
    if email_type in ['imap', 'pop3', 'both']:
        # Test IMAP/POP3 ports
        mail_ports = {
            110: 'POP3',
            995: 'POP3S (secure)',
            143: 'IMAP',
            993: 'IMAPS (secure)'
        }
        
        for port, desc in mail_ports.items():
            result = check_single_port(mail_server, port)
            results['services'][desc] = result
            
            if port in [993, 995] and result['open']:
                results['diagnosis'].append(f"Secure {desc} is available")
    
    # Analyze results
    open_services = [s for s, r in results['services'].items() if r['open']]
    if not open_services:
        results['diagnosis'].append("No email services are accessible")
        results['recommendations'].extend([
            "Verify mail server address is correct",
            "Check firewall rules for email ports",
            "Confirm mail services are running"
        ])
    else:
        secure_services = [s for s in open_services if 'secure' in s.lower() or 'TLS' in s]
        if not secure_services:
            results['recommendations'].append(
                "Consider using secure email protocols (SMTPS, IMAPS, SMTP-TLS)"
            )
    
    return results


def diagnose_database_connection(db_host: str, db_type: str = None) -> Dict[str, Any]:
    """
    Diagnose database connectivity issues
    
    Args:
        db_host: Database server hostname
        db_type: Database type (mysql, postgresql, mssql, etc.) or None to check all
    
    Returns:
        Diagnostic results for database connectivity
    """
    # Database port mappings
    db_ports = {
        'mysql': 3306,
        'postgresql': 5432,
        'mssql': 1433,
        'oracle': 1521,
        'mongodb': 27017,
        'redis': 6379,
        'elasticsearch': 9200
    }
    
    results = {
        'db_host': db_host,
        'diagnosis': [],
        'recommendations': [],
        'databases': {}
    }
    
    if db_type:
        # Check specific database
        if db_type in db_ports:
            port = db_ports[db_type]
            result = check_single_port(db_host, port)
            results['databases'][db_type] = result
            
            if result['open']:
                results['diagnosis'].append(f"{db_type} port is open")
                results['recommendations'].append(
                    f"Database port is accessible, check credentials and database configuration"
                )
            else:
                results['diagnosis'].append(f"{db_type} port is closed")
                results['recommendations'].extend([
                    f"Verify {db_type} service is running",
                    f"Check firewall rules for port {port}",
                    "Confirm database is configured to accept network connections"
                ])
        else:
            results['diagnosis'].append(f"Unknown database type: {db_type}")
    else:
        # Check all common databases
        for db_name, port in db_ports.items():
            result = check_single_port(db_host, port)
            if result['open']:
                results['databases'][db_name] = result
                results['diagnosis'].append(f"Found open {db_name} port")
        
        if not any(r['open'] for r in results['databases'].values()):
            results['diagnosis'].append("No common database ports are open")
            results['recommendations'].append(
                "Specify the database type or check if using non-standard ports"
            )
    
    return results


def perform_health_check(services: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Perform a comprehensive health check on multiple services
    
    Args:
        services: List of services to check, each containing:
                 - name: Service name
                 - host: Hostname
                 - port: Port number
                 - critical: Boolean indicating if service is critical
    
    Returns:
        Overall health status and individual service results
    """
    results = test_service_chain(services, stop_on_failure=False)
    
    # Enhance with criticality analysis
    critical_failures = [
        s['name'] for s in services 
        if s.get('critical', False) and 
        not any(r['open'] for r in results['services'] if r['name'] == s['name'])
    ]
    
    if critical_failures:
        results['overall_status'] = 'critical'
        results['critical_failures'] = critical_failures
    
    # Add health score
    total_services = len(services)
    healthy_services = len([s for s in results['services'] if s['open']])
    results['health_score'] = round((healthy_services / total_services) * 100, 2)
    
    return results