"""
OpenVAS Integration Module

This module provides functions to integrate with OpenVAS vulnerability scanner,
including API client, scan scheduling, and results parsing for Claude Code orchestration.
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from datetime import datetime
import time
import base64
from enum import Enum

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ScanStatus(Enum):
    """OpenVAS scan status values."""
    REQUESTED = "Requested"
    QUEUED = "Queued"
    RUNNING = "Running"
    STOP_REQUESTED = "Stop Requested"
    STOPPED = "Stopped"
    DONE = "Done"
    ERROR = "Error"
    INTERRUPTED = "Interrupted"


class OpenVASClient:
    """OpenVAS API client for vulnerability scanning operations."""
    
    def __init__(self, host: str, port: int = 9392, username: str = None, 
                 password: str = None, timeout: int = 30):
        """
        Initialize OpenVAS client.
        
        Args:
            host: OpenVAS server hostname or IP
            port: OpenVAS API port (default: 9392)
            username: OpenVAS username
            password: OpenVAS password
            timeout: Request timeout in seconds
        """
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # OpenVAS often uses self-signed certificates
        self.token = None
        
    def authenticate(self) -> bool:
        """
        Authenticate with OpenVAS server.
        
        Returns:
            bool: True if authentication successful
        """
        try:
            # Create authentication XML
            auth_xml = f"""
            <authenticate>
                <credentials>
                    <username>{self.username}</username>
                    <password>{self.password}</password>
                </credentials>
            </authenticate>
            """
            
            response = self._send_command(auth_xml, skip_auth=True)
            
            if response and 'authenticate_response' in response:
                status = response.get('authenticate_response', {}).get('@status')
                if status == '200':
                    self.token = response['authenticate_response'].get('token')
                    logger.info("Successfully authenticated with OpenVAS")
                    return True
                    
            logger.error("OpenVAS authentication failed")
            return False
            
        except Exception as e:
            logger.error(f"OpenVAS authentication error: {e}")
            return False
            
    def create_target(self, name: str, hosts: str, port_list_id: str = None) -> Optional[str]:
        """
        Create a scan target.
        
        Args:
            name: Target name
            hosts: Comma-separated list of hosts/IPs
            port_list_id: Port list ID (optional, uses default if not specified)
            
        Returns:
            str: Target ID if successful, None otherwise
        """
        if not port_list_id:
            # Use default port list
            port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # All IANA assigned TCP
            
        cmd_xml = f"""
        <create_target>
            <name>{name}</name>
            <hosts>{hosts}</hosts>
            <port_list id="{port_list_id}"/>
        </create_target>
        """
        
        response = self._send_command(cmd_xml)
        if response and 'create_target_response' in response:
            return response['create_target_response'].get('@id')
        return None
        
    def create_task(self, name: str, target_id: str, scanner_id: str = None,
                    config_id: str = None) -> Optional[str]:
        """
        Create a scan task.
        
        Args:
            name: Task name
            target_id: Target ID
            scanner_id: Scanner ID (optional, uses default)
            config_id: Scan config ID (optional, uses Full and fast)
            
        Returns:
            str: Task ID if successful, None otherwise
        """
        if not scanner_id:
            scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"  # Default OpenVAS scanner
            
        if not config_id:
            config_id = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
            
        cmd_xml = f"""
        <create_task>
            <name>{name}</name>
            <target id="{target_id}"/>
            <scanner id="{scanner_id}"/>
            <config id="{config_id}"/>
        </create_task>
        """
        
        response = self._send_command(cmd_xml)
        if response and 'create_task_response' in response:
            return response['create_task_response'].get('@id')
        return None
        
    def start_task(self, task_id: str) -> bool:
        """
        Start a scan task.
        
        Args:
            task_id: Task ID to start
            
        Returns:
            bool: True if started successfully
        """
        cmd_xml = f'<start_task task_id="{task_id}"/>'
        
        response = self._send_command(cmd_xml)
        if response and 'start_task_response' in response:
            status = response['start_task_response'].get('@status')
            return status == '202'
        return False
        
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get task status and progress.
        
        Args:
            task_id: Task ID
            
        Returns:
            dict: Task status information
        """
        cmd_xml = f'<get_tasks task_id="{task_id}"/>'
        
        response = self._send_command(cmd_xml)
        if response and 'get_tasks_response' in response:
            task = response['get_tasks_response'].get('task', {})
            return {
                'status': task.get('status'),
                'progress': task.get('progress'),
                'report_id': task.get('last_report', {}).get('@id')
            }
        return None
        
    def get_report(self, report_id: str, format_id: str = None) -> Optional[Dict[str, Any]]:
        """
        Get scan report.
        
        Args:
            report_id: Report ID
            format_id: Report format ID (optional, uses XML by default)
            
        Returns:
            dict: Report data
        """
        if not format_id:
            format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"  # XML format
            
        cmd_xml = f'<get_reports report_id="{report_id}" format_id="{format_id}"/>'
        
        response = self._send_command(cmd_xml)
        if response and 'get_reports_response' in response:
            return response['get_reports_response'].get('report')
        return None
        
    def _send_command(self, xml_command: str, skip_auth: bool = False) -> Optional[Dict]:
        """
        Send XML command to OpenVAS.
        
        Args:
            xml_command: XML command string
            skip_auth: Skip authentication header
            
        Returns:
            dict: Parsed response or None
        """
        headers = {'Content-Type': 'application/xml'}
        
        if not skip_auth and self.token:
            headers['Cookie'] = f'token={self.token}'
            
        try:
            response = self.session.post(
                f"{self.base_url}/omp",
                data=xml_command,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                # Parse XML response
                return self._parse_xml_response(response.text)
            else:
                logger.error(f"OpenVAS API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"OpenVAS request error: {e}")
            return None
            
    def _parse_xml_response(self, xml_text: str) -> Dict:
        """Parse XML response to dictionary."""
        try:
            root = ET.fromstring(xml_text)
            return self._xml_to_dict(root)
        except Exception as e:
            logger.error(f"XML parsing error: {e}")
            return {}
            
    def _xml_to_dict(self, element) -> Dict:
        """Convert XML element to dictionary."""
        result = {}
        
        # Add attributes
        for key, value in element.attrib.items():
            result[f'@{key}'] = value
            
        # Add text content
        if element.text and element.text.strip():
            result['text'] = element.text.strip()
            
        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                # Convert to list if multiple elements with same tag
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
                
        return result


class ScanScheduler:
    """Scheduler for OpenVAS scans."""
    
    def __init__(self, client: OpenVASClient):
        """
        Initialize scan scheduler.
        
        Args:
            client: OpenVAS client instance
        """
        self.client = client
        self.scheduled_scans = {}
        
    def schedule_scan(self, name: str, targets: List[str], 
                     schedule_time: datetime = None,
                     scan_config: str = "full") -> Optional[str]:
        """
        Schedule a vulnerability scan.
        
        Args:
            name: Scan name
            targets: List of target hosts/IPs
            schedule_time: When to run scan (immediate if None)
            scan_config: Scan configuration (full, fast, ultimate)
            
        Returns:
            str: Scheduled scan ID
        """
        # Map scan configs to OpenVAS config IDs
        config_map = {
            "full": "daba56c8-73ec-11df-a475-002264764cea",  # Full and fast
            "fast": "8715c877-47a0-438d-98a3-27c7a6ab2196",  # Discovery
            "ultimate": "698f691e-7489-11df-9d8c-002264764cea"  # Ultimate
        }
        
        config_id = config_map.get(scan_config, config_map["full"])
        
        # Create target
        target_name = f"{name}_target_{int(time.time())}"
        target_id = self.client.create_target(target_name, ",".join(targets))
        
        if not target_id:
            logger.error("Failed to create scan target")
            return None
            
        # Create task
        task_name = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        task_id = self.client.create_task(task_name, target_id, config_id=config_id)
        
        if not task_id:
            logger.error("Failed to create scan task")
            return None
            
        # Schedule or start immediately
        if schedule_time and schedule_time > datetime.now():
            # Store for later execution
            self.scheduled_scans[task_id] = {
                'name': name,
                'schedule_time': schedule_time,
                'status': 'scheduled'
            }
            logger.info(f"Scan scheduled for {schedule_time}")
        else:
            # Start immediately
            if self.client.start_task(task_id):
                logger.info(f"Scan started: {task_id}")
            else:
                logger.error("Failed to start scan")
                return None
                
        return task_id
        
    def check_scheduled_scans(self):
        """Check and start scheduled scans that are due."""
        current_time = datetime.now()
        
        for task_id, scan_info in list(self.scheduled_scans.items()):
            if scan_info['status'] == 'scheduled' and scan_info['schedule_time'] <= current_time:
                if self.client.start_task(task_id):
                    scan_info['status'] = 'running'
                    logger.info(f"Started scheduled scan: {task_id}")
                else:
                    scan_info['status'] = 'error'
                    logger.error(f"Failed to start scheduled scan: {task_id}")


class ResultParser:
    """Parser for OpenVAS scan results."""
    
    @staticmethod
    def parse_report(report_data: Dict) -> Dict[str, Any]:
        """
        Parse OpenVAS report to standardized format.
        
        Args:
            report_data: Raw report data from OpenVAS
            
        Returns:
            dict: Parsed vulnerability data
        """
        vulnerabilities = []
        
        # Extract results from report
        results = report_data.get('results', {}).get('result', [])
        if not isinstance(results, list):
            results = [results]
            
        for result in results:
            vuln = ResultParser._parse_vulnerability(result)
            if vuln:
                vulnerabilities.append(vuln)
                
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
            'scan_id': report_data.get('@id'),
            'scan_time': report_data.get('creation_time'),
            'target': report_data.get('task', {}).get('target', {}).get('name'),
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                'by_severity': severity_counts
            }
        }
        
    @staticmethod
    def _parse_vulnerability(result: Dict) -> Optional[Dict[str, Any]]:
        """Parse individual vulnerability from result."""
        try:
            # Extract severity
            severity = float(result.get('severity', 0))
            if severity >= 9.0:
                severity_label = 'CRITICAL'
            elif severity >= 7.0:
                severity_label = 'HIGH'
            elif severity >= 4.0:
                severity_label = 'MEDIUM'
            elif severity >= 0.1:
                severity_label = 'LOW'
            else:
                severity_label = 'INFO'
                
            # Extract CVE if present
            nvt = result.get('nvt', {})
            cve = nvt.get('cve', 'NOCVE')
            
            return {
                'vulnerability_id': result.get('@id'),
                'name': result.get('name'),
                'description': result.get('description'),
                'host': result.get('host'),
                'port': result.get('port'),
                'severity': severity,
                'severity_label': severity_label,
                'cve': cve if cve != 'NOCVE' else None,
                'solution': nvt.get('solution'),
                'references': nvt.get('refs', {}).get('ref', []),
                'detection_method': result.get('detection', {}).get('result', {}).get('details')
            }
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability: {e}")
            return None


# Convenience functions for Claude Code orchestration

def quick_scan(host: str, openvas_config: Dict[str, str]) -> Dict[str, Any]:
    """
    Perform a quick vulnerability scan on a single host.
    
    Args:
        host: Target host/IP
        openvas_config: Configuration with 'host', 'username', 'password'
        
    Returns:
        dict: Scan results
        
    Example:
        >>> config = {'host': 'openvas.local', 'username': 'admin', 'password': 'admin'}
        >>> results = quick_scan('192.168.1.100', config)
        >>> print(f"Found {results['summary']['total']} vulnerabilities")
    """
    client = OpenVASClient(
        host=openvas_config['host'],
        username=openvas_config['username'],
        password=openvas_config['password']
    )
    
    if not client.authenticate():
        return {'error': 'Authentication failed'}
        
    scheduler = ScanScheduler(client)
    task_id = scheduler.schedule_scan("Quick Scan", [host], scan_config="fast")
    
    if not task_id:
        return {'error': 'Failed to create scan'}
        
    # Wait for scan to complete
    max_wait = 300  # 5 minutes
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        status = client.get_task_status(task_id)
        if status and status['status'] == 'Done':
            # Get and parse report
            report = client.get_report(status['report_id'])
            if report:
                return ResultParser.parse_report(report)
            break
        time.sleep(10)
        
    return {'error': 'Scan timeout or failed'}


def scan_network(network: str, openvas_config: Dict[str, str],
                scan_type: str = "full") -> Dict[str, Any]:
    """
    Scan an entire network for vulnerabilities.
    
    Args:
        network: Network in CIDR notation (e.g., '192.168.1.0/24')
        openvas_config: OpenVAS configuration
        scan_type: Type of scan (full, fast, ultimate)
        
    Returns:
        dict: Scan results for all hosts
    """
    client = OpenVASClient(
        host=openvas_config['host'],
        username=openvas_config['username'],
        password=openvas_config['password']
    )
    
    if not client.authenticate():
        return {'error': 'Authentication failed'}
        
    scheduler = ScanScheduler(client)
    task_id = scheduler.schedule_scan(
        f"Network Scan {network}",
        [network],
        scan_config=scan_type
    )
    
    if not task_id:
        return {'error': 'Failed to create scan'}
        
    logger.info(f"Network scan started: {task_id}")
    return {'task_id': task_id, 'status': 'running', 'network': network}


def get_scan_results(task_id: str, openvas_config: Dict[str, str]) -> Dict[str, Any]:
    """
    Retrieve results of a completed scan.
    
    Args:
        task_id: Task ID from previous scan
        openvas_config: OpenVAS configuration
        
    Returns:
        dict: Parsed scan results
    """
    client = OpenVASClient(
        host=openvas_config['host'],
        username=openvas_config['username'],
        password=openvas_config['password']
    )
    
    if not client.authenticate():
        return {'error': 'Authentication failed'}
        
    status = client.get_task_status(task_id)
    if not status:
        return {'error': 'Task not found'}
        
    if status['status'] != 'Done':
        return {
            'status': status['status'],
            'progress': status.get('progress', 0),
            'message': 'Scan not complete'
        }
        
    # Get and parse report
    report = client.get_report(status['report_id'])
    if report:
        return ResultParser.parse_report(report)
        
    return {'error': 'Failed to retrieve report'}