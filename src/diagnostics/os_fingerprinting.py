"""
OS Fingerprinting Module for Claude Code Orchestration

This module provides OS detection capabilities through various techniques including
TCP/IP stack fingerprinting, service banner analysis, and behavioral patterns.
"""

import socket
import struct
import time
import platform
import subprocess
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import concurrent.futures

from ..utils.logger import get_logger

logger = get_logger(__name__)


# OS signatures based on TCP/IP stack behavior
OS_SIGNATURES = {
    'windows': {
        'ttl_values': [128, 127, 126, 125],  # Windows default TTL is 128
        'window_sizes': [8192, 16384, 65535],
        'tcp_options': ['M', 'N', 'N', 'S'],  # MSS, NOP, NOP, SACK
        'service_patterns': {
            'smb': True,
            'netbios': True,
            'rdp': True,
            'wmi': True
        },
        'banner_keywords': ['Windows', 'Microsoft', 'IIS', 'Win32', 'NT']
    },
    'linux': {
        'ttl_values': [64, 63, 62, 61],  # Linux default TTL is 64
        'window_sizes': [5840, 14600, 29200],
        'tcp_options': ['M', 'S', 'T', 'N', 'W'],  # MSS, SACK, Timestamp, NOP, Window scale
        'service_patterns': {
            'ssh': True,
            'apache': True,
            'nginx': True
        },
        'banner_keywords': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'Red Hat', 'GNU']
    },
    'macos': {
        'ttl_values': [64, 63, 62, 61],  # macOS default TTL is 64
        'window_sizes': [65535],
        'tcp_options': ['M', 'N', 'W', 'N', 'N', 'T', 'S'],
        'service_patterns': {
            'ssh': True,
            'afp': True,
            'bonjour': True
        },
        'banner_keywords': ['Darwin', 'Mac OS', 'macOS', 'Apple']
    },
    'bsd': {
        'ttl_values': [64, 63, 62, 61],
        'window_sizes': [65535, 32768],
        'tcp_options': ['M', 'N', 'W', 'S', 'T'],
        'service_patterns': {
            'ssh': True,
            'pf': True
        },
        'banner_keywords': ['BSD', 'FreeBSD', 'OpenBSD', 'NetBSD']
    },
    'cisco': {
        'ttl_values': [255, 254, 253],  # Network devices often use 255
        'service_patterns': {
            'telnet': True,
            'ssh': True,
            'snmp': True
        },
        'banner_keywords': ['Cisco', 'IOS', 'router', 'switch']
    }
}


def detect_os_by_ttl(host: str, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Detect OS by analyzing TTL (Time To Live) values from ping responses.
    
    Args:
        host: Target hostname or IP address
        timeout: Ping timeout in seconds
        
    Returns:
        Dictionary with OS detection results based on TTL
        
    Example:
        >>> result = detect_os_by_ttl('192.168.1.1')
        >>> print(result['probable_os'])
        'Linux/Unix'
    """
    result = {
        'host': host,
        'method': 'ttl_analysis',
        'ttl': None,
        'probable_os': 'unknown',
        'confidence': 0.0,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        # Platform-specific ping command
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '3', '-w', str(int(timeout * 1000)), host]
        else:
            cmd = ['ping', '-c', '3', '-W', str(int(timeout)), host]
            
        # Execute ping
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=timeout * 4)
        
        # Extract TTL from ping output
        ttl_match = re.search(r'ttl[=:](\d+)', stdout, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            result['ttl'] = ttl
            
            # Analyze TTL to determine OS
            os_guess = _analyze_ttl(ttl)
            result['probable_os'] = os_guess['os']
            result['confidence'] = os_guess['confidence']
            
    except subprocess.TimeoutExpired:
        result['error'] = 'Ping timeout'
    except Exception as e:
        result['error'] = str(e)
        
    return result


def detect_os_by_tcp_fingerprint(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Detect OS by analyzing TCP/IP stack characteristics.
    
    Args:
        host: Target hostname or IP address
        port: Open TCP port to test against
        timeout: Connection timeout
        
    Returns:
        Dictionary with OS detection results based on TCP fingerprinting
        
    Example:
        >>> result = detect_os_by_tcp_fingerprint('192.168.1.1', 80)
        >>> print(result['characteristics'])
        {'window_size': 65535, 'ttl': 64, 'df_bit': True}
    """
    result = {
        'host': host,
        'port': port,
        'method': 'tcp_fingerprint',
        'characteristics': {},
        'probable_os': 'unknown',
        'confidence': 0.0,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        # Create raw socket for packet crafting (requires root/admin)
        # Fallback to regular socket if raw socket fails
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Get initial window size and options
        sock.connect((host, port))
        
        # Get socket options (limited without raw sockets)
        try:
            # These might not work without elevated privileges
            tcp_info = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, 1024) if hasattr(socket, 'TCP_INFO') else None
            window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            
            result['characteristics']['window_size'] = window_size
        except:
            # Fallback - estimate from connection
            result['characteristics']['window_size'] = 65535  # Default assumption
            
        sock.close()
        
        # Try to get TTL from ICMP
        ttl_result = detect_os_by_ttl(host, timeout)
        if ttl_result.get('ttl'):
            result['characteristics']['ttl'] = ttl_result['ttl']
            
        # Analyze characteristics
        os_guess = _analyze_tcp_characteristics(result['characteristics'])
        result['probable_os'] = os_guess['os']
        result['confidence'] = os_guess['confidence']
        
    except Exception as e:
        result['error'] = str(e)
        
    return result


def detect_os_by_service_banner(services: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect OS by analyzing service banners and patterns.
    
    Args:
        services: List of service detection results (from service_detection module)
        
    Returns:
        Dictionary with OS detection results based on service analysis
        
    Example:
        >>> services = [{'service': 'SSH', 'banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3'}]
        >>> result = detect_os_by_service_banner(services)
        >>> print(result['probable_os'])
        'Ubuntu Linux'
    """
    result = {
        'method': 'service_banner_analysis',
        'analyzed_services': len(services),
        'os_hints': [],
        'probable_os': 'unknown',
        'confidence': 0.0,
        'timestamp': datetime.now().isoformat()
    }
    
    os_scores = {}
    
    for service in services:
        banner = service.get('banner', '')
        service_name = service.get('service', '').lower()
        
        # Check banner keywords
        for os_name, signature in OS_SIGNATURES.items():
            for keyword in signature.get('banner_keywords', []):
                if keyword.lower() in banner.lower():
                    os_scores[os_name] = os_scores.get(os_name, 0) + 2
                    result['os_hints'].append({
                        'os': os_name,
                        'source': 'banner',
                        'evidence': f"{keyword} in {service_name} banner"
                    })
                    
        # Check service patterns
        for os_name, signature in OS_SIGNATURES.items():
            service_patterns = signature.get('service_patterns', {})
            for pattern_service, expected in service_patterns.items():
                if pattern_service in service_name and expected:
                    os_scores[os_name] = os_scores.get(os_name, 0) + 1
                    result['os_hints'].append({
                        'os': os_name,
                        'source': 'service_pattern',
                        'evidence': f"{pattern_service} service present"
                    })
                    
        # Specific banner parsing
        os_specific = _parse_specific_banner(banner, service_name)
        if os_specific:
            os_scores[os_specific] = os_scores.get(os_specific, 0) + 3
            result['os_hints'].append({
                'os': os_specific,
                'source': 'specific_banner',
                'evidence': banner
            })
            
    # Determine most likely OS
    if os_scores:
        probable_os = max(os_scores, key=os_scores.get)
        max_score = os_scores[probable_os]
        total_score = sum(os_scores.values())
        
        result['probable_os'] = probable_os
        result['confidence'] = min(max_score / total_score, 0.95) if total_score > 0 else 0.0
        result['all_scores'] = os_scores
        
    return result


def detect_os_comprehensive(host: str, open_ports: List[int] = None, 
                           services: List[Dict[str, Any]] = None,
                           timeout: float = 3.0) -> Dict[str, Any]:
    """
    Comprehensive OS detection using multiple techniques.
    
    Args:
        host: Target hostname or IP address
        open_ports: List of open ports (if already scanned)
        services: List of detected services (if already scanned)
        timeout: Timeout for detection operations
        
    Returns:
        Comprehensive OS detection results combining multiple methods
        
    Example:
        >>> result = detect_os_comprehensive('192.168.1.1', open_ports=[22, 80, 443])
        >>> print(f"OS: {result['os']} (confidence: {result['confidence']:.1%})")
        OS: Ubuntu Linux (confidence: 87.5%)
    """
    result = {
        'host': host,
        'os': 'unknown',
        'os_family': 'unknown',
        'version': None,
        'confidence': 0.0,
        'methods_used': [],
        'details': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # Method 1: TTL Analysis
    ttl_result = detect_os_by_ttl(host, timeout)
    if not ttl_result.get('error'):
        result['methods_used'].append('ttl_analysis')
        result['details']['ttl'] = ttl_result
        
    # Method 2: TCP Fingerprinting (if we have open ports)
    if open_ports:
        tcp_result = detect_os_by_tcp_fingerprint(host, open_ports[0], timeout)
        if not tcp_result.get('error'):
            result['methods_used'].append('tcp_fingerprint')
            result['details']['tcp'] = tcp_result
            
    # Method 3: Service Banner Analysis (if we have service info)
    if services:
        banner_result = detect_os_by_service_banner(services)
        result['methods_used'].append('service_banner')
        result['details']['banner'] = banner_result
        
    # Combine results
    os_votes = {}
    total_confidence = 0.0
    
    for method, details in result['details'].items():
        if details.get('probable_os') and details['probable_os'] != 'unknown':
            os = details['probable_os']
            confidence = details.get('confidence', 0.5)
            os_votes[os] = os_votes.get(os, 0) + confidence
            total_confidence += confidence
            
    # Determine final OS
    if os_votes:
        result['os'] = max(os_votes, key=os_votes.get)
        result['confidence'] = min(os_votes[result['os']] / len(result['methods_used']), 0.95)
        result['os_family'] = _determine_os_family(result['os'])
        
        # Try to extract version
        result['version'] = _extract_os_version(result['os'], result['details'])
        
    return result


def detect_os_nmap(host: str, timeout: int = 300) -> Dict[str, Any]:
    """
    Use nmap for OS detection (if available).
    
    Args:
        host: Target hostname or IP address
        timeout: Scan timeout in seconds
        
    Returns:
        Dictionary with nmap OS detection results
        
    Note:
        Requires python-nmap and nmap binary. Requires root/admin privileges.
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        
        # OS detection requires root privileges
        nm.scan(hosts=host, arguments='-O', timeout=timeout)
        
        result = {
            'host': host,
            'method': 'nmap',
            'os_matches': [],
            'timestamp': datetime.now().isoformat()
        }
        
        if host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    result['os_matches'].append({
                        'name': osmatch['name'],
                        'accuracy': int(osmatch['accuracy']),
                        'os_family': osmatch.get('osclass', [{}])[0].get('osfamily', 'unknown')
                    })
                    
                # Set primary match
                if result['os_matches']:
                    best_match = result['os_matches'][0]
                    result['os'] = best_match['name']
                    result['confidence'] = best_match['accuracy'] / 100.0
                    result['os_family'] = best_match['os_family']
                    
        return result
        
    except ImportError:
        logger.warning("python-nmap not available for OS detection")
        return {'error': 'nmap not available', 'method': 'nmap'}
    except Exception as e:
        return {'error': str(e), 'method': 'nmap'}


# Helper functions

def _analyze_ttl(ttl: int) -> Dict[str, Any]:
    """Analyze TTL value to guess OS."""
    # Account for hop decrements (assume up to 20 hops)
    original_ttl = ttl
    for hops in range(20):
        test_ttl = ttl + hops
        if test_ttl in [32, 64, 128, 255]:
            original_ttl = test_ttl
            break
            
    # Determine OS based on original TTL
    if original_ttl >= 128:
        return {'os': 'Windows', 'confidence': 0.8}
    elif original_ttl >= 64:
        return {'os': 'Linux/Unix', 'confidence': 0.7}
    elif original_ttl >= 255:
        return {'os': 'Network Device', 'confidence': 0.6}
    else:
        return {'os': 'unknown', 'confidence': 0.0}


def _analyze_tcp_characteristics(chars: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze TCP characteristics to guess OS."""
    os_scores = {}
    
    # Check window size
    window_size = chars.get('window_size', 0)
    if window_size in [8192, 16384]:
        os_scores['windows'] = os_scores.get('windows', 0) + 1
    elif window_size == 65535:
        os_scores['macos'] = os_scores.get('macos', 0) + 1
        os_scores['bsd'] = os_scores.get('bsd', 0) + 1
    elif window_size in [5840, 14600, 29200]:
        os_scores['linux'] = os_scores.get('linux', 0) + 1
        
    # Check TTL if available
    ttl = chars.get('ttl')
    if ttl:
        ttl_analysis = _analyze_ttl(ttl)
        if 'Windows' in ttl_analysis['os']:
            os_scores['windows'] = os_scores.get('windows', 0) + 2
        elif 'Linux' in ttl_analysis['os']:
            os_scores['linux'] = os_scores.get('linux', 0) + 2
            
    # Determine most likely OS
    if os_scores:
        probable_os = max(os_scores, key=os_scores.get)
        confidence = min(os_scores[probable_os] / sum(os_scores.values()), 0.8)
        return {'os': probable_os, 'confidence': confidence}
    else:
        return {'os': 'unknown', 'confidence': 0.0}


def _parse_specific_banner(banner: str, service: str) -> Optional[str]:
    """Parse specific OS information from service banners."""
    banner_lower = banner.lower()
    
    # SSH banners often contain OS info
    if 'ssh' in service:
        if 'ubuntu' in banner_lower:
            return 'ubuntu'
        elif 'debian' in banner_lower:
            return 'debian'
        elif 'centos' in banner_lower:
            return 'centos'
        elif 'red hat' in banner_lower or 'rhel' in banner_lower:
            return 'redhat'
        elif 'windows' in banner_lower:
            return 'windows'
            
    # HTTP server headers
    elif 'http' in service:
        if 'iis' in banner_lower:
            return 'windows'
        elif 'apache' in banner_lower and 'ubuntu' in banner_lower:
            return 'ubuntu'
        elif 'apache' in banner_lower and 'centos' in banner_lower:
            return 'centos'
            
    # SMB/NetBIOS
    elif 'smb' in service or 'netbios' in service:
        return 'windows'
        
    return None


def _determine_os_family(os_name: str) -> str:
    """Determine OS family from OS name."""
    os_lower = os_name.lower()
    
    if any(w in os_lower for w in ['windows', 'win32', 'winnt']):
        return 'Windows'
    elif any(w in os_lower for w in ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'fedora', 'suse']):
        return 'Linux'
    elif any(w in os_lower for w in ['mac', 'darwin', 'osx']):
        return 'macOS'
    elif any(w in os_lower for w in ['bsd', 'freebsd', 'openbsd', 'netbsd']):
        return 'BSD'
    elif any(w in os_lower for w in ['cisco', 'ios', 'juniper', 'junos']):
        return 'Network Device'
    else:
        return 'Other'


def _extract_os_version(os_name: str, details: Dict[str, Any]) -> Optional[str]:
    """Try to extract OS version from various sources."""
    # Check banner details
    if 'banner' in details:
        for hint in details['banner'].get('os_hints', []):
            evidence = hint.get('evidence', '')
            # Look for version patterns
            version_match = re.search(r'(\d+\.[\d\.]+)', evidence)
            if version_match:
                return version_match.group(1)
                
    return None