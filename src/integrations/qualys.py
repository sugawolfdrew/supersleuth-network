"""
Qualys Integration Module

This module provides functions to integrate with Qualys vulnerability management platform,
including API client, scan management, and results processing for Claude Code orchestration.
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import time
import base64
from urllib.parse import urlencode

from ..utils.logger import get_logger

logger = get_logger(__name__)


class QualysClient:
    """Qualys API client for vulnerability management operations."""
    
    def __init__(self, platform_url: str, username: str, password: str,
                 verify_ssl: bool = True):
        """
        Initialize Qualys client.
        
        Args:
            platform_url: Qualys platform URL (e.g., https://qualysapi.qualys.com)
            username: Qualys username
            password: Qualys password
            verify_ssl: Verify SSL certificates
        """
        self.base_url = platform_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Set up basic authentication
        auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.session.headers.update({
            'Authorization': f'Basic {auth_string}',
            'X-Requested-With': 'Python Qualys Client'
        })
        
    def test_connection(self) -> bool:
        """
        Test connection to Qualys API.
        
        Returns:
            bool: True if connection successful
        """
        try:
            response = self.session.get(
                f"{self.base_url}/api/2.0/fo/auth/",
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Qualys connection test failed: {e}")
            return False
            
    def list_option_profiles(self) -> List[Dict[str, Any]]:
        """
        List available option profiles.
        
        Returns:
            list: Option profiles
        """
        response = self._api_request(
            'GET',
            '/api/2.0/fo/subscription/option_profile/search/',
            {'action': 'list'}
        )
        
        if response:
            return self._parse_option_profiles(response)
        return []
        
    def add_ip(self, ips: str, tracking_method: str = "IP",
               enable_vm: bool = True, enable_pc: bool = False) -> bool:
        """
        Add IP addresses to Qualys subscription.
        
        Args:
            ips: Comma-separated IP addresses or ranges
            tracking_method: Asset tracking method
            enable_vm: Enable vulnerability management
            enable_pc: Enable policy compliance
            
        Returns:
            bool: True if successful
        """
        params = {
            'action': 'add',
            'ips': ips,
            'tracking_method': tracking_method
        }
        
        if enable_vm:
            params['enable_vm'] = 1
        if enable_pc:
            params['enable_pc'] = 1
            
        response = self._api_request('POST', '/api/2.0/fo/asset/ip/', params)
        return self._check_response_success(response)
        
    def launch_scan(self, scan_title: str, ips: str, option_profile: str = None,
                   scanner_name: str = None) -> Optional[str]:
        """
        Launch a vulnerability scan.
        
        Args:
            scan_title: Scan title
            ips: Target IPs (comma-separated)
            option_profile: Option profile name
            scanner_name: Scanner appliance name
            
        Returns:
            str: Scan reference ID if successful
        """
        params = {
            'action': 'launch',
            'scan_title': scan_title,
            'ip': ips,
            'iscanner_name': scanner_name or 'External'
        }
        
        if option_profile:
            params['option_profile'] = option_profile
        else:
            params['option_profile'] = 'Initial Options'  # Default profile
            
        response = self._api_request('POST', '/api/2.0/fo/scan/', params)
        
        if response:
            # Extract scan reference from response
            scan_ref = self._extract_scan_reference(response)
            if scan_ref:
                logger.info(f"Scan launched: {scan_ref}")
                return scan_ref
                
        return None
        
    def get_scan_status(self, scan_ref: str) -> Optional[Dict[str, Any]]:
        """
        Get scan status.
        
        Args:
            scan_ref: Scan reference ID
            
        Returns:
            dict: Scan status information
        """
        params = {
            'action': 'list',
            'scan_ref': scan_ref,
            'show_status': 1
        }
        
        response = self._api_request('GET', '/api/2.0/fo/scan/', params)
        
        if response:
            scan_info = self._parse_scan_status(response)
            if scan_info:
                return scan_info
                
        return None
        
    def get_scan_results(self, scan_ref: str, output_format: str = "json") -> Optional[Dict[str, Any]]:
        """
        Get scan results.
        
        Args:
            scan_ref: Scan reference ID
            output_format: Output format (json, xml, csv)
            
        Returns:
            dict: Scan results
        """
        # First, check if scan is complete
        status = self.get_scan_status(scan_ref)
        if not status or status.get('state') != 'Finished':
            logger.warning(f"Scan {scan_ref} is not complete")
            return None
            
        # Download scan results
        params = {
            'action': 'fetch',
            'scan_ref': scan_ref,
            'output_format': output_format,
            'mode': 'extended'  # Get detailed results
        }
        
        response = self._api_request('GET', '/api/2.0/fo/scan/', params, raw=True)
        
        if response:
            if output_format == 'json':
                return response.json()
            else:
                return {'raw_data': response.text}
                
        return None
        
    def list_vulnerabilities(self, ips: str = None, qids: str = None,
                           severities: str = None) -> List[Dict[str, Any]]:
        """
        List vulnerabilities for specific IPs or QIDs.
        
        Args:
            ips: Target IPs (comma-separated)
            qids: Qualys IDs (comma-separated)
            severities: Severity levels (1-5, comma-separated)
            
        Returns:
            list: Vulnerability records
        """
        params = {'action': 'list'}
        
        if ips:
            params['ips'] = ips
        if qids:
            params['qids'] = qids
        if severities:
            params['severities'] = severities
            
        response = self._api_request('POST', '/api/2.0/fo/asset/host/vm/detection/', params)
        
        if response:
            return self._parse_vulnerabilities(response)
            
        return []
        
    def get_vulnerability_details(self, qid: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific vulnerability.
        
        Args:
            qid: Qualys vulnerability ID
            
        Returns:
            dict: Vulnerability details
        """
        params = {
            'action': 'list',
            'ids': str(qid),
            'details': 'All'
        }
        
        response = self._api_request('POST', '/api/2.0/fo/knowledge_base/vuln/', params)
        
        if response:
            vulns = self._parse_knowledge_base(response)
            if vulns:
                return vulns[0]  # Return first (and only) result
                
        return None
        
    def create_report(self, template_id: str, report_title: str,
                     report_format: str = "pdf", ips: str = None) -> Optional[int]:
        """
        Create a vulnerability report.
        
        Args:
            template_id: Report template ID
            report_title: Report title
            report_format: Output format (pdf, csv, xml)
            ips: Target IPs for report
            
        Returns:
            int: Report ID if successful
        """
        params = {
            'action': 'launch',
            'template_id': template_id,
            'report_title': report_title,
            'output_format': report_format
        }
        
        if ips:
            params['ips'] = ips
            
        response = self._api_request('POST', '/api/2.0/fo/report/', params)
        
        if response:
            report_id = self._extract_report_id(response)
            if report_id:
                logger.info(f"Report created: {report_id}")
                return report_id
                
        return None
        
    def download_report(self, report_id: int) -> Optional[bytes]:
        """
        Download a completed report.
        
        Args:
            report_id: Report ID
            
        Returns:
            bytes: Report content
        """
        params = {
            'action': 'fetch',
            'id': report_id
        }
        
        response = self._api_request('GET', '/api/2.0/fo/report/', params, raw=True)
        
        if response:
            return response.content
            
        return None
        
    def _api_request(self, method: str, endpoint: str, params: Dict = None,
                    raw: bool = False) -> Optional[Any]:
        """
        Make API request to Qualys.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            params: Request parameters
            raw: Return raw response
            
        Returns:
            Response data or None
        """
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method == 'GET':
                response = self.session.get(url, params=params, timeout=60)
            elif method == 'POST':
                response = self.session.post(url, data=params, timeout=60)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            if response.status_code == 200:
                if raw:
                    return response
                else:
                    return response.text
            else:
                logger.error(f"Qualys API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Qualys API request error: {e}")
            return None
            
    def _check_response_success(self, response_text: str) -> bool:
        """Check if API response indicates success."""
        if not response_text:
            return False
            
        try:
            root = ET.fromstring(response_text)
            response_code = root.find('.//CODE')
            if response_code is not None:
                return response_code.text == '0'
        except:
            pass
            
        return 'success' in response_text.lower()
        
    def _extract_scan_reference(self, response_text: str) -> Optional[str]:
        """Extract scan reference from launch response."""
        try:
            root = ET.fromstring(response_text)
            scan_ref = root.find('.//VALUE')
            if scan_ref is not None:
                return scan_ref.text
        except Exception as e:
            logger.error(f"Error extracting scan reference: {e}")
            
        return None
        
    def _extract_report_id(self, response_text: str) -> Optional[int]:
        """Extract report ID from launch response."""
        try:
            root = ET.fromstring(response_text)
            report_id = root.find('.//VALUE')
            if report_id is not None:
                return int(report_id.text)
        except Exception as e:
            logger.error(f"Error extracting report ID: {e}")
            
        return None
        
    def _parse_scan_status(self, response_text: str) -> Optional[Dict[str, Any]]:
        """Parse scan status from response."""
        try:
            root = ET.fromstring(response_text)
            scan = root.find('.//SCAN')
            
            if scan is not None:
                return {
                    'ref': scan.find('REF').text if scan.find('REF') is not None else None,
                    'title': scan.find('TITLE').text if scan.find('TITLE') is not None else None,
                    'state': scan.find('STATE').text if scan.find('STATE') is not None else None,
                    'targets': scan.find('TARGET').text if scan.find('TARGET') is not None else None,
                    'duration': scan.find('DURATION').text if scan.find('DURATION') is not None else None,
                    'processed': scan.find('PROCESSED').text if scan.find('PROCESSED') is not None else 0
                }
        except Exception as e:
            logger.error(f"Error parsing scan status: {e}")
            
        return None
        
    def _parse_vulnerabilities(self, response_text: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from response."""
        vulnerabilities = []
        
        try:
            root = ET.fromstring(response_text)
            
            for host in root.findall('.//HOST'):
                host_ip = host.find('IP').text if host.find('IP') is not None else 'Unknown'
                
                for detection in host.findall('.//DETECTION'):
                    vuln = {
                        'host': host_ip,
                        'qid': detection.find('QID').text if detection.find('QID') is not None else None,
                        'type': detection.find('TYPE').text if detection.find('TYPE') is not None else None,
                        'severity': detection.find('SEVERITY').text if detection.find('SEVERITY') is not None else None,
                        'port': detection.find('PORT').text if detection.find('PORT') is not None else None,
                        'protocol': detection.find('PROTOCOL').text if detection.find('PROTOCOL') is not None else None,
                        'ssl': detection.find('SSL').text if detection.find('SSL') is not None else None,
                        'result': detection.find('RESULT').text if detection.find('RESULT') is not None else None,
                        'first_found': detection.find('FIRST_FOUND_DATETIME').text if detection.find('FIRST_FOUND_DATETIME') is not None else None,
                        'last_found': detection.find('LAST_FOUND_DATETIME').text if detection.find('LAST_FOUND_DATETIME') is not None else None
                    }
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Error parsing vulnerabilities: {e}")
            
        return vulnerabilities
        
    def _parse_knowledge_base(self, response_text: str) -> List[Dict[str, Any]]:
        """Parse vulnerability details from knowledge base."""
        vulns = []
        
        try:
            root = ET.fromstring(response_text)
            
            for vuln_elem in root.findall('.//VULN'):
                vuln = {
                    'qid': vuln_elem.find('QID').text if vuln_elem.find('QID') is not None else None,
                    'title': vuln_elem.find('TITLE').text if vuln_elem.find('TITLE') is not None else None,
                    'category': vuln_elem.find('CATEGORY').text if vuln_elem.find('CATEGORY') is not None else None,
                    'severity': vuln_elem.find('SEVERITY_LEVEL').text if vuln_elem.find('SEVERITY_LEVEL') is not None else None,
                    'detection_info': vuln_elem.find('DETECTION_INFO').text if vuln_elem.find('DETECTION_INFO') is not None else None,
                    'consequence': vuln_elem.find('CONSEQUENCE').text if vuln_elem.find('CONSEQUENCE') is not None else None,
                    'solution': vuln_elem.find('SOLUTION').text if vuln_elem.find('SOLUTION') is not None else None,
                    'cvss_base': vuln_elem.find('.//BASE').text if vuln_elem.find('.//BASE') is not None else None,
                    'cvss_temporal': vuln_elem.find('.//TEMPORAL').text if vuln_elem.find('.//TEMPORAL') is not None else None,
                    'cvss_vector': vuln_elem.find('.//VECTOR_STRING').text if vuln_elem.find('.//VECTOR_STRING') is not None else None,
                    'cve_list': []
                }
                
                # Extract CVE IDs
                for cve in vuln_elem.findall('.//CVE_ID'):
                    if cve.text:
                        vuln['cve_list'].append(cve.text)
                        
                vulns.append(vuln)
                
        except Exception as e:
            logger.error(f"Error parsing knowledge base: {e}")
            
        return vulns
        
    def _parse_option_profiles(self, response_text: str) -> List[Dict[str, str]]:
        """Parse option profiles from response."""
        profiles = []
        
        try:
            root = ET.fromstring(response_text)
            
            for profile in root.findall('.//OPTION_PROFILE'):
                profile_info = {
                    'id': profile.find('ID').text if profile.find('ID') is not None else None,
                    'title': profile.find('TITLE').text if profile.find('TITLE') is not None else None,
                    'is_default': profile.find('IS_DEFAULT').text if profile.find('IS_DEFAULT') is not None else 'no'
                }
                profiles.append(profile_info)
                
        except Exception as e:
            logger.error(f"Error parsing option profiles: {e}")
            
        return profiles


class ResultAdapter:
    """Adapts Qualys results to common format."""
    
    @staticmethod
    def normalize_scan_results(vulnerabilities: List[Dict], kb_cache: Dict = None) -> Dict[str, Any]:
        """
        Normalize Qualys scan results to common format.
        
        Args:
            vulnerabilities: List of vulnerabilities from Qualys
            kb_cache: Cache of vulnerability details from knowledge base
            
        Returns:
            dict: Normalized vulnerability data
        """
        if kb_cache is None:
            kb_cache = {}
            
        normalized_vulns = []
        
        for vuln in vulnerabilities:
            qid = vuln.get('qid')
            
            # Get additional details from knowledge base cache
            kb_info = kb_cache.get(qid, {})
            
            # Normalize severity
            severity = int(vuln.get('severity', 0))
            if severity == 5:
                severity_label = 'CRITICAL'
            elif severity == 4:
                severity_label = 'HIGH'
            elif severity == 3:
                severity_label = 'MEDIUM'
            elif severity == 2:
                severity_label = 'LOW'
            else:
                severity_label = 'INFO'
                
            normalized = {
                'vulnerability_id': f"qualys-{qid}",
                'qid': qid,
                'name': kb_info.get('title', f'QID {qid}'),
                'description': kb_info.get('detection_info', ''),
                'host': vuln.get('host'),
                'port': vuln.get('port', 0),
                'protocol': vuln.get('protocol', 'tcp'),
                'severity': severity,
                'severity_label': severity_label,
                'cvss_score': kb_info.get('cvss_base'),
                'cvss_vector': kb_info.get('cvss_vector'),
                'cve': kb_info.get('cve_list', []),
                'solution': kb_info.get('solution'),
                'consequence': kb_info.get('consequence'),
                'first_detected': vuln.get('first_found'),
                'last_detected': vuln.get('last_found'),
                'scan_type': vuln.get('type')
            }
            
            normalized_vulns.append(normalized)
            
        # Summary statistics
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        hosts_affected = set()
        
        for vuln in normalized_vulns:
            severity = vuln['severity_label'].lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            hosts_affected.add(vuln['host'])
            
        return {
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': normalized_vulns,
            'summary': {
                'total': len(normalized_vulns),
                'by_severity': severity_counts,
                'hosts_affected': len(hosts_affected)
            }
        }


# Convenience functions for Claude Code orchestration

def run_vulnerability_scan(targets: str, qualys_config: Dict[str, str],
                         scan_profile: str = None) -> Dict[str, Any]:
    """
    Run a vulnerability scan on specified targets.
    
    Args:
        targets: Comma-separated list of targets
        qualys_config: Configuration with 'platform_url', 'username', 'password'
        scan_profile: Option profile name (uses default if not specified)
        
    Returns:
        dict: Scan results
        
    Example:
        >>> config = {
        ...     'platform_url': 'https://qualysapi.qualys.com',
        ...     'username': 'your-username',
        ...     'password': 'your-password'
        ... }
        >>> results = run_vulnerability_scan('192.168.1.0/24', config)
        >>> print(f"Found {results['summary']['total']} vulnerabilities")
    """
    client = QualysClient(
        platform_url=qualys_config['platform_url'],
        username=qualys_config['username'],
        password=qualys_config['password']
    )
    
    if not client.test_connection():
        return {'error': 'Connection to Qualys failed'}
        
    # Add IPs to subscription if needed
    if not client.add_ip(targets):
        logger.warning("Failed to add IPs to subscription, they may already exist")
        
    # Launch scan
    scan_title = f"Vulnerability Scan - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_ref = client.launch_scan(scan_title, targets, scan_profile)
    
    if not scan_ref:
        return {'error': 'Failed to launch scan'}
        
    logger.info(f"Scan launched with reference: {scan_ref}")
    
    # Wait for completion
    max_wait = 3600  # 1 hour
    start_time = time.time()
    check_interval = 30  # Check every 30 seconds
    
    while time.time() - start_time < max_wait:
        status = client.get_scan_status(scan_ref)
        
        if status and status.get('state') == 'Finished':
            # Get vulnerabilities
            vulns = client.list_vulnerabilities(ips=targets)
            
            # Get unique QIDs for knowledge base lookup
            unique_qids = list(set(v.get('qid') for v in vulns if v.get('qid')))
            
            # Fetch vulnerability details from knowledge base
            kb_cache = {}
            for qid in unique_qids:
                details = client.get_vulnerability_details(int(qid))
                if details:
                    kb_cache[qid] = details
                    
            # Normalize results
            return ResultAdapter.normalize_scan_results(vulns, kb_cache)
            
        elif status and status.get('state') in ['Error', 'Cancelled']:
            return {'error': f"Scan failed with state: {status.get('state')}"}
            
        time.sleep(check_interval)
        
    return {'error': 'Scan timeout'}


def get_asset_vulnerabilities(asset_ip: str, qualys_config: Dict[str, str],
                            severity_filter: str = None) -> Dict[str, Any]:
    """
    Get all vulnerabilities for a specific asset.
    
    Args:
        asset_ip: Target IP address
        qualys_config: Qualys configuration
        severity_filter: Filter by severity (1-5, comma-separated)
        
    Returns:
        dict: Vulnerability information for the asset
    """
    client = QualysClient(
        platform_url=qualys_config['platform_url'],
        username=qualys_config['username'],
        password=qualys_config['password']
    )
    
    # Get vulnerabilities
    vulns = client.list_vulnerabilities(ips=asset_ip, severities=severity_filter)
    
    if not vulns:
        return {
            'asset': asset_ip,
            'vulnerabilities': [],
            'summary': {'total': 0}
        }
        
    # Get unique QIDs for knowledge base lookup
    unique_qids = list(set(v.get('qid') for v in vulns if v.get('qid')))
    
    # Fetch vulnerability details
    kb_cache = {}
    for qid in unique_qids:
        details = client.get_vulnerability_details(int(qid))
        if details:
            kb_cache[qid] = details
            
    # Normalize results
    normalized = ResultAdapter.normalize_scan_results(vulns, kb_cache)
    normalized['asset'] = asset_ip
    
    return normalized


def generate_compliance_report(template_id: str, targets: str,
                             qualys_config: Dict[str, str],
                             report_format: str = "pdf") -> Dict[str, Any]:
    """
    Generate a compliance or vulnerability report.
    
    Args:
        template_id: Qualys report template ID
        targets: Target IPs for report
        qualys_config: Qualys configuration
        report_format: Output format (pdf, csv, xml)
        
    Returns:
        dict: Report generation status
    """
    client = QualysClient(
        platform_url=qualys_config['platform_url'],
        username=qualys_config['username'],
        password=qualys_config['password']
    )
    
    # Create report
    report_title = f"Vulnerability Report - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_id = client.create_report(template_id, report_title, report_format, targets)
    
    if not report_id:
        return {'error': 'Failed to create report'}
        
    # Wait for report generation
    max_wait = 600  # 10 minutes
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        # Try to download report
        content = client.download_report(report_id)
        
        if content:
            return {
                'report_id': report_id,
                'status': 'completed',
                'size': len(content),
                'content': content
            }
            
        time.sleep(30)  # Check every 30 seconds
        
    return {
        'report_id': report_id,
        'status': 'timeout',
        'message': 'Report generation timed out'
    }