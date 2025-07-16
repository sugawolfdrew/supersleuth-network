"""
Diagnostic API for Claude Code Orchestration

This module provides a unified API interface for Claude Code to orchestrate
various network diagnostic tools. It acts as the main entry point for
diagnostic operations.
"""

import json
import time
from typing import Dict, List, Optional, Any, Union, Callable
from datetime import datetime
import concurrent.futures
from enum import Enum

from . import service_detection
from . import os_fingerprinting
from . import script_scanning
from . import security_scanner
from . import network_discovery
from ..utils.logger import get_logger

logger = get_logger(__name__)


class DiagnosticType(Enum):
    """Available diagnostic types."""
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    OS_DETECTION = "os_detection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    SCRIPT_SCAN = "script_scan"
    NETWORK_DISCOVERY = "network_discovery"
    FULL_SCAN = "full_scan"
    QUICK_SCAN = "quick_scan"
    WEB_SCAN = "web_scan"
    DATABASE_SCAN = "database_scan"


class NetworkDiagnosticAPI:
    """
    Main API class for orchestrating network diagnostics.
    
    This class provides a unified interface for Claude Code to run various
    network diagnostic tools and combine their results.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the diagnostic API.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.results_cache = {}
        self.logger = get_logger(__name__)
        
    def run_diagnostic(self, target: str, diagnostic_type: Union[str, DiagnosticType], 
                      **kwargs) -> Dict[str, Any]:
        """
        Run a specific diagnostic on a target.
        
        Args:
            target: Target hostname or IP address
            diagnostic_type: Type of diagnostic to run
            **kwargs: Additional parameters for the diagnostic
            
        Returns:
            Dictionary with diagnostic results
            
        Example:
            >>> api = NetworkDiagnosticAPI()
            >>> result = api.run_diagnostic('192.168.1.1', 'port_scan', ports='1-1000')
            >>> print(f"Found {len(result['open_ports'])} open ports")
        """
        # Convert string to enum if needed
        if isinstance(diagnostic_type, str):
            try:
                diagnostic_type = DiagnosticType(diagnostic_type)
            except ValueError:
                return {
                    'error': f"Invalid diagnostic type: {diagnostic_type}",
                    'valid_types': [t.value for t in DiagnosticType]
                }
                
        # Log the diagnostic request
        self.logger.info(f"Running {diagnostic_type.value} diagnostic on {target}")
        
        # Route to appropriate handler
        handlers = {
            DiagnosticType.PORT_SCAN: self._run_port_scan,
            DiagnosticType.SERVICE_DETECTION: self._run_service_detection,
            DiagnosticType.OS_DETECTION: self._run_os_detection,
            DiagnosticType.VULNERABILITY_SCAN: self._run_vulnerability_scan,
            DiagnosticType.SCRIPT_SCAN: self._run_script_scan,
            DiagnosticType.NETWORK_DISCOVERY: self._run_network_discovery,
            DiagnosticType.FULL_SCAN: self._run_full_scan,
            DiagnosticType.QUICK_SCAN: self._run_quick_scan,
            DiagnosticType.WEB_SCAN: self._run_web_scan,
            DiagnosticType.DATABASE_SCAN: self._run_database_scan
        }
        
        handler = handlers.get(diagnostic_type)
        if handler:
            return handler(target, **kwargs)
        else:
            return {'error': f"Handler not implemented for {diagnostic_type.value}"}
            
    def run_workflow(self, target: str, workflow: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run a custom diagnostic workflow.
        
        Args:
            target: Target hostname or IP address
            workflow: List of diagnostic steps to run
            
        Returns:
            Combined results from all workflow steps
            
        Example:
            >>> workflow = [
            ...     {'type': 'port_scan', 'params': {'ports': '1-1000'}},
            ...     {'type': 'service_detection', 'use_previous': 'open_ports'},
            ...     {'type': 'vulnerability_scan', 'use_previous': 'services'}
            ... ]
            >>> results = api.run_workflow('192.168.1.1', workflow)
        """
        results = {
            'target': target,
            'workflow': workflow,
            'steps': {},
            'summary': {},
            'timestamp': datetime.now().isoformat()
        }
        
        context = {'target': target}
        
        for i, step in enumerate(workflow):
            step_name = f"step_{i}_{step['type']}"
            self.logger.info(f"Running workflow step {i+1}/{len(workflow)}: {step['type']}")
            
            # Get parameters
            params = step.get('params', {})
            
            # Use results from previous steps if specified
            if 'use_previous' in step:
                prev_key = step['use_previous']
                if prev_key in context:
                    params[prev_key] = context[prev_key]
                    
            # Run the diagnostic
            step_result = self.run_diagnostic(target, step['type'], **params)
            results['steps'][step_name] = step_result
            
            # Update context for next steps
            if 'open_ports' in step_result:
                context['open_ports'] = step_result['open_ports']
            if 'services' in step_result:
                context['services'] = step_result['services']
                
        # Generate summary
        results['summary'] = self._generate_workflow_summary(results['steps'])
        
        return results
        
    def analyze_target(self, target: str, analysis_depth: str = 'standard') -> Dict[str, Any]:
        """
        Perform intelligent analysis of a target.
        
        Args:
            target: Target hostname or IP address
            analysis_depth: 'quick', 'standard', or 'deep'
            
        Returns:
            Comprehensive analysis results
            
        Example:
            >>> analysis = api.analyze_target('example.com', 'deep')
            >>> print(analysis['recommendations'])
        """
        self.logger.info(f"Performing {analysis_depth} analysis of {target}")
        
        if analysis_depth == 'quick':
            # Quick scan - just common ports and basic service detection
            workflow = [
                {'type': 'port_scan', 'params': {'ports': '21,22,23,25,80,443,3389,8080'}},
                {'type': 'service_detection', 'use_previous': 'open_ports'}
            ]
        elif analysis_depth == 'deep':
            # Deep scan - comprehensive analysis
            workflow = [
                {'type': 'port_scan', 'params': {'ports': '1-65535'}},
                {'type': 'service_detection', 'use_previous': 'open_ports'},
                {'type': 'os_detection', 'use_previous': 'open_ports'},
                {'type': 'vulnerability_scan', 'use_previous': 'services'},
                {'type': 'script_scan', 'params': {'category': 'safe'}}
            ]
        else:
            # Standard scan - balanced approach
            workflow = [
                {'type': 'port_scan', 'params': {'ports': '1-10000'}},
                {'type': 'service_detection', 'use_previous': 'open_ports'},
                {'type': 'os_detection', 'use_previous': 'open_ports'},
                {'type': 'vulnerability_scan', 'use_previous': 'services'}
            ]
            
        # Run the workflow
        results = self.run_workflow(target, workflow)
        
        # Add intelligent analysis
        results['analysis'] = self._perform_intelligent_analysis(results)
        results['recommendations'] = self._generate_recommendations(results)
        results['risk_assessment'] = self._assess_risk(results)
        
        return results
        
    # Diagnostic handlers
    
    def _run_port_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run port scanning diagnostic."""
        ports = kwargs.get('ports', '1-1000')
        timeout = kwargs.get('timeout', 1.0)
        
        # Parse port specification
        port_list = self._parse_port_spec(ports)
        
        # Use security scanner for consistency
        if len(port_list) == 1:
            result = security_scanner.scan_tcp_port(target, port_list[0], timeout)
            open_ports = [result] if result['state'] == 'open' else []
        else:
            results = security_scanner.scan_tcp_ports_batch(target, port_list, timeout)
            open_ports = [r for r in results if r['state'] == 'open']
            
        return {
            'target': target,
            'scan_type': 'port_scan',
            'ports_scanned': len(port_list),
            'open_ports': open_ports,
            'timestamp': datetime.now().isoformat()
        }
        
    def _run_service_detection(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run service detection diagnostic."""
        # Get ports to scan
        if 'open_ports' in kwargs:
            # Use provided open ports
            ports = [p['port'] for p in kwargs['open_ports']]
        elif 'ports' in kwargs:
            # Use specified ports
            ports = self._parse_port_spec(kwargs['ports'])
        else:
            # Scan well-known services
            return {
                'target': target,
                'scan_type': 'service_detection',
                'services': service_detection.scan_well_known_services(target),
                'timestamp': datetime.now().isoformat()
            }
            
        # Detect services on specified ports
        services = service_detection.detect_services_batch(target, ports)
        
        # Try nmap if available
        nmap_result = service_detection.detect_services_nmap(target, kwargs.get('ports'))
        
        return {
            'target': target,
            'scan_type': 'service_detection',
            'services': services,
            'nmap_available': nmap_result.get('scan_method') == 'nmap',
            'detailed_results': nmap_result if nmap_result.get('scan_method') == 'nmap' else None,
            'timestamp': datetime.now().isoformat()
        }
        
    def _run_os_detection(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run OS detection diagnostic."""
        open_ports = kwargs.get('open_ports', [])
        services = kwargs.get('services', [])
        
        # Extract port numbers if needed
        if open_ports and isinstance(open_ports[0], dict):
            port_numbers = [p['port'] for p in open_ports]
        else:
            port_numbers = open_ports
            
        # Run comprehensive OS detection
        result = os_fingerprinting.detect_os_comprehensive(
            target, 
            open_ports=port_numbers,
            services=services
        )
        
        # Try nmap if available
        nmap_result = os_fingerprinting.detect_os_nmap(target)
        if not nmap_result.get('error'):
            result['nmap_detection'] = nmap_result
            
        return result
        
    def _run_vulnerability_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run vulnerability scanning diagnostic."""
        services = kwargs.get('services', [])
        scan_depth = kwargs.get('scan_depth', 'standard')
        
        # Use security scanner
        scan_type = 'full' if scan_depth == 'deep' else 'basic'
        vuln_results = security_scanner.perform_security_scan(target, scan_type)
        
        # Add script-based vulnerability scanning
        if services:
            script_results = script_scanning.run_script_category(
                target, services, 'vuln'
            )
            vuln_results['script_vulnerabilities'] = script_results['vulnerabilities']
            
        return vuln_results
        
    def _run_script_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run script-based scanning."""
        services = kwargs.get('services', [])
        category = kwargs.get('category', 'safe')
        
        # If no services provided, do a quick service scan first
        if not services:
            svc_result = self._run_service_detection(target)
            services = svc_result.get('services', [])
            
        return script_scanning.run_script_category(target, services, category)
        
    def _run_network_discovery(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run network discovery diagnostic."""
        # This would integrate with the existing NetworkDiscovery class
        # For now, return a placeholder
        return {
            'target': target,
            'scan_type': 'network_discovery',
            'message': 'Network discovery requires subnet authorization',
            'timestamp': datetime.now().isoformat()
        }
        
    def _run_full_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run comprehensive full scan."""
        return self.analyze_target(target, 'deep')
        
    def _run_quick_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run quick scan of common services."""
        return self.analyze_target(target, 'quick')
        
    def _run_web_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run web-specific diagnostics."""
        port = kwargs.get('port', 443 if kwargs.get('https', True) else 80)
        
        # Check if web service is running
        port_result = security_scanner.scan_tcp_port(target, port)
        
        if port_result['state'] != 'open':
            return {
                'target': target,
                'scan_type': 'web_scan',
                'error': f"Port {port} is not open",
                'timestamp': datetime.now().isoformat()
            }
            
        # Run web-specific scans
        results = {
            'target': target,
            'scan_type': 'web_scan',
            'port': port,
            'timestamp': datetime.now().isoformat()
        }
        
        # HTTP/HTTPS vulnerabilities
        http_vulns = script_scanning.scan_http_vulnerabilities(
            target, port, ssl_enabled=(port == 443)
        )
        results['http_vulnerabilities'] = http_vulns
        
        # SSL/TLS analysis if HTTPS
        if port == 443 or kwargs.get('https'):
            ssl_vulns = script_scanning.scan_ssl_vulnerabilities(target, port)
            results['ssl_vulnerabilities'] = ssl_vulns
            
        return results
        
    def _run_database_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run database-specific diagnostics."""
        db_type = kwargs.get('db_type')
        port = kwargs.get('port')
        
        # Auto-detect if not specified
        if not db_type or not port:
            # Scan common database ports
            db_ports = {
                3306: 'mysql',
                5432: 'postgresql',
                27017: 'mongodb',
                6379: 'redis',
                1433: 'mssql'
            }
            
            for p, db in db_ports.items():
                if security_scanner.scan_tcp_port(target, p)['state'] == 'open':
                    port = p
                    db_type = db
                    break
                    
        if not db_type:
            return {
                'target': target,
                'scan_type': 'database_scan',
                'error': 'No database service detected',
                'timestamp': datetime.now().isoformat()
            }
            
        # Run database security scan
        return script_scanning.scan_database_security(target, port, db_type)
        
    # Helper methods
    
    def _parse_port_spec(self, ports: str) -> List[int]:
        """Parse port specification string."""
        port_list = []
        
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
                
        return port_list
        
    def _generate_workflow_summary(self, steps: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary from workflow steps."""
        summary = {
            'total_open_ports': 0,
            'detected_services': [],
            'os_detection': None,
            'vulnerabilities': [],
            'risk_level': 'unknown'
        }
        
        for step_name, result in steps.items():
            if 'open_ports' in result:
                summary['total_open_ports'] = len(result['open_ports'])
            if 'services' in result:
                summary['detected_services'] = [s.get('service', 'unknown') for s in result['services']]
            if 'os' in result:
                summary['os_detection'] = result['os']
            if 'vulnerabilities' in result:
                summary['vulnerabilities'].extend(result['vulnerabilities'])
                
        # Calculate risk level
        if summary['vulnerabilities']:
            critical_vulns = [v for v in summary['vulnerabilities'] if v.get('severity') == 'critical']
            high_vulns = [v for v in summary['vulnerabilities'] if v.get('severity') == 'high']
            
            if critical_vulns:
                summary['risk_level'] = 'critical'
            elif high_vulns:
                summary['risk_level'] = 'high'
            else:
                summary['risk_level'] = 'medium'
        else:
            summary['risk_level'] = 'low'
            
        return summary
        
    def _perform_intelligent_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform intelligent analysis of scan results."""
        analysis = {
            'security_posture': 'unknown',
            'key_findings': [],
            'attack_surface': [],
            'compliance_issues': []
        }
        
        # Analyze results
        summary = results.get('summary', {})
        
        # Security posture assessment
        if summary.get('risk_level') == 'critical':
            analysis['security_posture'] = 'poor'
        elif summary.get('risk_level') == 'high':
            analysis['security_posture'] = 'needs_improvement'
        elif summary.get('total_open_ports', 0) > 20:
            analysis['security_posture'] = 'excessive_exposure'
        else:
            analysis['security_posture'] = 'reasonable'
            
        # Key findings
        if summary.get('vulnerabilities'):
            analysis['key_findings'].append(
                f"Found {len(summary['vulnerabilities'])} vulnerabilities"
            )
            
        if summary.get('total_open_ports', 0) > 0:
            analysis['key_findings'].append(
                f"{summary['total_open_ports']} open ports detected"
            )
            
        # Attack surface
        for service in summary.get('detected_services', []):
            if service.lower() in ['telnet', 'ftp', 'vnc']:
                analysis['attack_surface'].append(f"Insecure service: {service}")
            elif service.lower() in ['ssh', 'rdp']:
                analysis['attack_surface'].append(f"Remote access: {service}")
            elif service.lower() in ['http', 'https']:
                analysis['attack_surface'].append(f"Web service: {service}")
                
        return analysis
        
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations."""
        recommendations = []
        summary = results.get('summary', {})
        
        # Check for critical vulnerabilities
        for vuln in summary.get('vulnerabilities', []):
            if vuln.get('severity') == 'critical':
                recommendations.append({
                    'priority': 'critical',
                    'action': f"Patch {vuln.get('type', 'vulnerability')}",
                    'description': vuln.get('description', 'Critical vulnerability detected'),
                    'effort': 'high'
                })
                
        # Check for insecure services
        insecure_services = ['telnet', 'ftp', 'vnc']
        for service in summary.get('detected_services', []):
            if service.lower() in insecure_services:
                recommendations.append({
                    'priority': 'high',
                    'action': f"Replace {service} with secure alternative",
                    'description': f"{service} transmits data in plaintext",
                    'effort': 'medium'
                })
                
        # Check for excessive open ports
        if summary.get('total_open_ports', 0) > 20:
            recommendations.append({
                'priority': 'medium',
                'action': 'Review and close unnecessary ports',
                'description': 'Large attack surface due to many open ports',
                'effort': 'low'
            })
            
        return recommendations
        
    def _assess_risk(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk level."""
        risk_score = 0
        risk_factors = []
        
        summary = results.get('summary', {})
        
        # Score based on vulnerabilities
        for vuln in summary.get('vulnerabilities', []):
            if vuln.get('severity') == 'critical':
                risk_score += 10
                risk_factors.append('Critical vulnerabilities present')
            elif vuln.get('severity') == 'high':
                risk_score += 5
                risk_factors.append('High severity vulnerabilities')
            elif vuln.get('severity') == 'medium':
                risk_score += 2
                
        # Score based on services
        high_risk_services = ['telnet', 'ftp', 'vnc']
        for service in summary.get('detected_services', []):
            if service.lower() in high_risk_services:
                risk_score += 3
                risk_factors.append(f"High-risk service: {service}")
                
        # Score based on exposure
        open_ports = summary.get('total_open_ports', 0)
        if open_ports > 50:
            risk_score += 5
            risk_factors.append('Excessive port exposure')
        elif open_ports > 20:
            risk_score += 2
            risk_factors.append('High port exposure')
            
        # Determine risk level
        if risk_score >= 20:
            risk_level = 'critical'
        elif risk_score >= 10:
            risk_level = 'high'
        elif risk_score >= 5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendation': self._get_risk_recommendation(risk_level)
        }
        
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            'critical': 'Immediate action required. Address critical vulnerabilities immediately.',
            'high': 'High priority remediation needed. Schedule fixes within 7 days.',
            'medium': 'Plan remediation within 30 days. Focus on high-impact issues.',
            'low': 'Maintain current security posture. Schedule regular reviews.'
        }
        return recommendations.get(risk_level, 'Perform regular security assessments.')


# Convenience functions for Claude Code

def quick_scan(target: str) -> Dict[str, Any]:
    """
    Perform a quick security scan of a target.
    
    Example:
        >>> result = quick_scan('192.168.1.1')
        >>> print(result['summary'])
    """
    api = NetworkDiagnosticAPI()
    return api.run_diagnostic(target, DiagnosticType.QUICK_SCAN)


def full_scan(target: str) -> Dict[str, Any]:
    """
    Perform a comprehensive scan of a target.
    
    Example:
        >>> result = full_scan('192.168.1.1')
        >>> print(result['recommendations'])
    """
    api = NetworkDiagnosticAPI()
    return api.run_diagnostic(target, DiagnosticType.FULL_SCAN)


def scan_web_application(target: str, https: bool = True) -> Dict[str, Any]:
    """
    Scan a web application for vulnerabilities.
    
    Example:
        >>> result = scan_web_application('example.com')
        >>> print(result['http_vulnerabilities'])
    """
    api = NetworkDiagnosticAPI()
    return api.run_diagnostic(target, DiagnosticType.WEB_SCAN, https=https)


def identify_services(target: str, ports: str = None) -> List[Dict[str, Any]]:
    """
    Identify services running on a target.
    
    Example:
        >>> services = identify_services('192.168.1.1', ports='1-1000')
        >>> for svc in services:
        ...     print(f"Port {svc['port']}: {svc['service']}")
    """
    api = NetworkDiagnosticAPI()
    result = api.run_diagnostic(target, DiagnosticType.SERVICE_DETECTION, ports=ports)
    return result.get('services', [])