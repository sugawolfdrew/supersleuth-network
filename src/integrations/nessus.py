"""
Nessus Integration Module

This module provides functions to integrate with Tenable Nessus vulnerability scanner,
including API client, scan configuration, and results parsing for Claude Code orchestration.
"""

import requests
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import time
from enum import Enum

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ScanStatus(Enum):
    """Nessus scan status values."""
    COMPLETED = "completed"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    CANCELED = "canceled"
    EMPTY = "empty"
    PROCESSING = "processing"
    ERROR = "error"


class NessusClient:
    """Nessus API client for vulnerability scanning operations."""
    
    def __init__(self, host: str, port: int = 8834, access_key: str = None,
                 secret_key: str = None, verify_ssl: bool = False):
        """
        Initialize Nessus client.
        
        Args:
            host: Nessus server hostname or IP
            port: Nessus API port (default: 8834)
            access_key: Nessus API access key
            secret_key: Nessus API secret key
            verify_ssl: Verify SSL certificates
        """
        self.base_url = f"https://{host}:{port}"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        if access_key and secret_key:
            self.headers['X-ApiKeys'] = f"accessKey={access_key}; secretKey={secret_key}"
            
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
    def test_connection(self) -> bool:
        """
        Test connection to Nessus server.
        
        Returns:
            bool: True if connection successful
        """
        try:
            response = self.session.get(
                f"{self.base_url}/server/properties",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Nessus connection test failed: {e}")
            return False
            
    def list_scan_templates(self) -> List[Dict[str, Any]]:
        """
        List available scan templates.
        
        Returns:
            list: Available scan templates
        """
        response = self._api_request('GET', '/editor/scan/templates')
        if response and 'templates' in response:
            return response['templates']
        return []
        
    def create_scan(self, name: str, targets: str, template_uuid: str = None,
                   description: str = "", folder_id: int = None) -> Optional[int]:
        """
        Create a new scan.
        
        Args:
            name: Scan name
            targets: Comma-separated list of targets
            template_uuid: Template UUID (uses basic if not specified)
            description: Scan description
            folder_id: Folder ID to store scan
            
        Returns:
            int: Scan ID if successful
        """
        if not template_uuid:
            # Use basic network scan template
            template_uuid = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d"
            
        payload = {
            "uuid": template_uuid,
            "settings": {
                "name": name,
                "description": description,
                "text_targets": targets
            }
        }
        
        if folder_id:
            payload["settings"]["folder_id"] = folder_id
            
        response = self._api_request('POST', '/scans', data=payload)
        if response and 'scan' in response:
            return response['scan']['id']
        return None
        
    def configure_scan(self, scan_id: int, settings: Dict[str, Any]) -> bool:
        """
        Configure scan settings.
        
        Args:
            scan_id: Scan ID
            settings: Scan settings dictionary
            
        Returns:
            bool: True if configuration successful
        """
        payload = {"settings": settings}
        response = self._api_request('PUT', f'/scans/{scan_id}', data=payload)
        return response is not None
        
    def launch_scan(self, scan_id: int) -> Optional[str]:
        """
        Launch a scan.
        
        Args:
            scan_id: Scan ID to launch
            
        Returns:
            str: Scan UUID if successful
        """
        response = self._api_request('POST', f'/scans/{scan_id}/launch')
        if response and 'scan_uuid' in response:
            return response['scan_uuid']
        return None
        
    def get_scan_status(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get scan status and details.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            dict: Scan status information
        """
        response = self._api_request('GET', f'/scans/{scan_id}')
        if response:
            info = response.get('info', {})
            return {
                'status': info.get('status'),
                'progress': info.get('progress', 0),
                'targets': info.get('targets'),
                'start_time': info.get('scan_start'),
                'end_time': info.get('scan_end')
            }
        return None
        
    def get_scan_results(self, scan_id: int, history_id: int = None) -> Optional[Dict[str, Any]]:
        """
        Get scan results.
        
        Args:
            scan_id: Scan ID
            history_id: History ID for specific run
            
        Returns:
            dict: Scan results
        """
        endpoint = f'/scans/{scan_id}'
        if history_id:
            endpoint += f'?history_id={history_id}'
            
        return self._api_request('GET', endpoint)
        
    def export_scan(self, scan_id: int, format: str = 'nessus',
                   history_id: int = None) -> Optional[str]:
        """
        Export scan results.
        
        Args:
            scan_id: Scan ID
            format: Export format (nessus, csv, pdf, html)
            history_id: History ID for specific run
            
        Returns:
            str: File UUID for download
        """
        payload = {"format": format}
        if history_id:
            payload["history_id"] = history_id
            
        response = self._api_request('POST', f'/scans/{scan_id}/export', data=payload)
        if response and 'file' in response:
            return response['file']
        return None
        
    def download_export(self, scan_id: int, file_id: str) -> Optional[bytes]:
        """
        Download exported scan file.
        
        Args:
            scan_id: Scan ID
            file_id: Export file ID
            
        Returns:
            bytes: File content
        """
        try:
            response = self.session.get(
                f"{self.base_url}/scans/{scan_id}/export/{file_id}/download",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 200:
                return response.content
        except Exception as e:
            logger.error(f"Export download error: {e}")
        return None
        
    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan.
        
        Args:
            scan_id: Scan ID to delete
            
        Returns:
            bool: True if deletion successful
        """
        response = self._api_request('DELETE', f'/scans/{scan_id}')
        return response is not None
        
    def _api_request(self, method: str, endpoint: str, data: Dict = None) -> Optional[Dict]:
        """
        Make API request to Nessus.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request payload
            
        Returns:
            dict: Response data or None
        """
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method == 'GET':
                response = self.session.get(url, headers=self.headers, timeout=30)
            elif method == 'POST':
                response = self.session.post(
                    url, 
                    headers=self.headers,
                    json=data,
                    timeout=30
                )
            elif method == 'PUT':
                response = self.session.put(
                    url,
                    headers=self.headers,
                    json=data,
                    timeout=30
                )
            elif method == 'DELETE':
                response = self.session.delete(url, headers=self.headers, timeout=30)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            if response.status_code in [200, 201]:
                return response.json() if response.text else {}
            else:
                logger.error(f"Nessus API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Nessus API request error: {e}")
            return None


class ScanConfiguration:
    """Helper class for building Nessus scan configurations."""
    
    # Common scan templates
    TEMPLATES = {
        'basic': '731a8e52-3ea6-a291-ec0a-d2ff0619c19d',
        'advanced': 'ad629e16-03b6-8c1d-cef6-ef8c9dd3c658',
        'webapp': 'ab4bacd2-05f6-425c-9d07-fea997c397d0',
        'malware': 'bc09dcbb-7b54-4b1b-bb62-de42ec3a9ab0',
        'mobile': '9a79ab6e-fcce-b628-1301-a29a4caa98a0',
        'pci': 'c4b208f8-2ba6-2059-e799-31ba48785110'
    }
    
    @staticmethod
    def create_basic_config(name: str, targets: str) -> Dict[str, Any]:
        """Create basic scan configuration."""
        return {
            'name': name,
            'text_targets': targets,
            'description': f'Basic network scan created at {datetime.now()}',
            'scanner_id': 1,
            'launch_now': False
        }
        
    @staticmethod
    def create_advanced_config(name: str, targets: str, **options) -> Dict[str, Any]:
        """
        Create advanced scan configuration.
        
        Options:
            port_range: Port range to scan
            ping_hosts: Ping hosts before scanning
            tcp_scanner: TCP port scanner type
            credentials: Dictionary of credentials
        """
        config = ScanConfiguration.create_basic_config(name, targets)
        
        # Port scanning
        if 'port_range' in options:
            config['portscan_range'] = options['port_range']
            
        # Host discovery
        if 'ping_hosts' in options:
            config['ping_the_remote_host'] = 'yes' if options['ping_hosts'] else 'no'
            
        # TCP scanner
        if 'tcp_scanner' in options:
            config['tcp_scanner'] = options['tcp_scanner']  # syn, connect, etc.
            
        # Credentials
        if 'credentials' in options:
            creds = options['credentials']
            if 'ssh' in creds:
                config['ssh_auth_method'] = creds['ssh'].get('auth_method', 'password')
                config['ssh_username'] = creds['ssh'].get('username')
                config['ssh_password'] = creds['ssh'].get('password')
                
        return config


class ResultNormalizer:
    """Normalizes Nessus results to common format."""
    
    @staticmethod
    def normalize_results(scan_data: Dict) -> Dict[str, Any]:
        """
        Normalize Nessus scan results to common format.
        
        Args:
            scan_data: Raw scan data from Nessus
            
        Returns:
            dict: Normalized vulnerability data
        """
        vulnerabilities = []
        hosts_data = scan_data.get('hosts', [])
        
        for host in hosts_data:
            host_vulns = ResultNormalizer._extract_host_vulnerabilities(
                host,
                scan_data.get('vulnerabilities', [])
            )
            vulnerabilities.extend(host_vulns)
            
        # Summary statistics
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln['severity_label'].lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
                
        return {
            'scan_id': scan_data.get('info', {}).get('object_id'),
            'scan_name': scan_data.get('info', {}).get('name'),
            'scan_time': scan_data.get('info', {}).get('timestamp'),
            'targets': scan_data.get('info', {}).get('targets'),
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                'by_severity': severity_counts,
                'hosts_scanned': len(hosts_data)
            }
        }
        
    @staticmethod
    def _extract_host_vulnerabilities(host: Dict, vuln_list: List[Dict]) -> List[Dict]:
        """Extract vulnerabilities for a specific host."""
        host_vulns = []
        host_ip = host.get('hostname')
        
        # Map vulnerability IDs to details
        vuln_map = {v['plugin_id']: v for v in vuln_list}
        
        # Process each vulnerability on this host
        for vuln_summary in host.get('vulnerabilities', []):
            plugin_id = vuln_summary.get('plugin_id')
            if plugin_id in vuln_map:
                vuln_detail = vuln_map[plugin_id]
                
                # Normalize severity
                severity = vuln_summary.get('severity', 0)
                if severity == 4:
                    severity_label = 'CRITICAL'
                elif severity == 3:
                    severity_label = 'HIGH'
                elif severity == 2:
                    severity_label = 'MEDIUM'
                elif severity == 1:
                    severity_label = 'LOW'
                else:
                    severity_label = 'INFO'
                    
                normalized_vuln = {
                    'vulnerability_id': f"nessus-{plugin_id}",
                    'plugin_id': plugin_id,
                    'name': vuln_detail.get('plugin_name'),
                    'description': vuln_detail.get('description'),
                    'host': host_ip,
                    'port': vuln_summary.get('port', 0),
                    'protocol': vuln_summary.get('protocol', 'tcp'),
                    'severity': severity,
                    'severity_label': severity_label,
                    'cvss_score': vuln_detail.get('cvss_base_score'),
                    'cvss_vector': vuln_detail.get('cvss_vector'),
                    'cve': vuln_detail.get('cve', []),
                    'solution': vuln_detail.get('solution'),
                    'risk_factor': vuln_detail.get('risk_factor'),
                    'plugin_family': vuln_detail.get('plugin_family'),
                    'plugin_publication_date': vuln_detail.get('plugin_publication_date')
                }
                
                host_vulns.append(normalized_vuln)
                
        return host_vulns


# Convenience functions for Claude Code orchestration

def perform_scan(targets: str, nessus_config: Dict[str, str],
                scan_type: str = "basic") -> Dict[str, Any]:
    """
    Perform a vulnerability scan on specified targets.
    
    Args:
        targets: Comma-separated list of targets
        nessus_config: Configuration with 'host', 'access_key', 'secret_key'
        scan_type: Type of scan (basic, advanced, webapp, malware, pci)
        
    Returns:
        dict: Scan results
        
    Example:
        >>> config = {
        ...     'host': 'nessus.local',
        ...     'access_key': 'your-access-key',
        ...     'secret_key': 'your-secret-key'
        ... }
        >>> results = perform_scan('192.168.1.0/24', config, 'basic')
        >>> print(f"Found {results['summary']['total']} vulnerabilities")
    """
    client = NessusClient(
        host=nessus_config['host'],
        access_key=nessus_config['access_key'],
        secret_key=nessus_config['secret_key']
    )
    
    if not client.test_connection():
        return {'error': 'Connection to Nessus failed'}
        
    # Get template UUID
    template_uuid = ScanConfiguration.TEMPLATES.get(scan_type, ScanConfiguration.TEMPLATES['basic'])
    
    # Create scan
    scan_name = f"{scan_type.title()} Scan - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_id = client.create_scan(scan_name, targets, template_uuid)
    
    if not scan_id:
        return {'error': 'Failed to create scan'}
        
    # Launch scan
    scan_uuid = client.launch_scan(scan_id)
    if not scan_uuid:
        return {'error': 'Failed to launch scan'}
        
    logger.info(f"Scan launched: {scan_id} ({scan_uuid})")
    
    # Wait for completion
    max_wait = 3600  # 1 hour
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        status = client.get_scan_status(scan_id)
        if status and status['status'] == ScanStatus.COMPLETED.value:
            # Get results
            results = client.get_scan_results(scan_id)
            if results:
                return ResultNormalizer.normalize_results(results)
            break
        elif status and status['status'] in [ScanStatus.ERROR.value, ScanStatus.CANCELED.value]:
            return {'error': f"Scan failed with status: {status['status']}"}
            
        time.sleep(30)  # Check every 30 seconds
        
    return {'error': 'Scan timeout'}


def check_scan_status(scan_id: int, nessus_config: Dict[str, str]) -> Dict[str, Any]:
    """
    Check the status of an ongoing scan.
    
    Args:
        scan_id: Scan ID to check
        nessus_config: Nessus configuration
        
    Returns:
        dict: Scan status information
    """
    client = NessusClient(
        host=nessus_config['host'],
        access_key=nessus_config['access_key'],
        secret_key=nessus_config['secret_key']
    )
    
    status = client.get_scan_status(scan_id)
    if status:
        return {
            'scan_id': scan_id,
            'status': status['status'],
            'progress': status['progress'],
            'is_complete': status['status'] == ScanStatus.COMPLETED.value
        }
        
    return {'error': 'Failed to get scan status'}


def get_vulnerability_details(scan_id: int, plugin_id: int,
                            nessus_config: Dict[str, str]) -> Dict[str, Any]:
    """
    Get detailed information about a specific vulnerability.
    
    Args:
        scan_id: Scan ID
        plugin_id: Plugin ID of the vulnerability
        nessus_config: Nessus configuration
        
    Returns:
        dict: Detailed vulnerability information
    """
    client = NessusClient(
        host=nessus_config['host'],
        access_key=nessus_config['access_key'],
        secret_key=nessus_config['secret_key']
    )
    
    # Get scan results
    results = client.get_scan_results(scan_id)
    if not results:
        return {'error': 'Failed to get scan results'}
        
    # Find the specific vulnerability
    for vuln in results.get('vulnerabilities', []):
        if vuln.get('plugin_id') == plugin_id:
            return {
                'plugin_id': plugin_id,
                'name': vuln.get('plugin_name'),
                'family': vuln.get('plugin_family'),
                'severity': vuln.get('severity'),
                'description': vuln.get('description'),
                'solution': vuln.get('solution'),
                'risk_factor': vuln.get('risk_factor'),
                'cvss_score': vuln.get('cvss_base_score'),
                'cvss_vector': vuln.get('cvss_vector'),
                'cve': vuln.get('cve', []),
                'references': vuln.get('see_also', []),
                'vuln_publication_date': vuln.get('vuln_publication_date'),
                'patch_publication_date': vuln.get('patch_publication_date'),
                'exploit_available': vuln.get('exploit_available', False),
                'exploitability_ease': vuln.get('exploitability_ease')
            }
            
    return {'error': 'Vulnerability not found'}