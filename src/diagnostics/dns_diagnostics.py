#!/usr/bin/env python3
"""
DNS Diagnostics Module
Comprehensive DNS troubleshooting tools for SuperSleuth Network

This module provides DNS diagnostic functions that Claude Code can use
to diagnose DNS-related network issues. Uses only Python standard library.
"""

import socket
import time
import subprocess
import platform
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils.logger import get_logger
from ..core.diagnostic import BaseDiagnostic, DiagnosticResult


logger = get_logger("DNSDiagnostics")


class DNSDiagnostics(BaseDiagnostic):
    """
    DNS diagnostic tools for troubleshooting name resolution issues
    
    This is often the first diagnostic to run when users report
    "can't connect to website/service" issues.
    """
    
    def __init__(self, config: Dict = None):
        if config is None:
            config = {'client_name': 'DNS Test'}
        super().__init__(config)
        self.name = "DNS Diagnostics"
        self.description = "Comprehensive DNS resolution testing"
        
        # Common DNS servers for testing
        self.public_dns_servers = {
            'Google Primary': '8.8.8.8',
            'Google Secondary': '8.8.4.4',
            'Cloudflare Primary': '1.1.1.1',
            'Cloudflare Secondary': '1.0.0.1',
            'OpenDNS Primary': '208.67.222.222',
            'OpenDNS Secondary': '208.67.220.220'
        }
        
        # Common test domains
        self.test_domains = [
            'google.com',
            'cloudflare.com',
            'github.com',
            'microsoft.com'
        ]
    
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        # DNS diagnostics only requires socket library
        return True
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        return {
            'read_only': True,
            'system_changes': False,
            'data_access': 'dns_queries_only',
            'risk_level': 'low',
            'description': 'Read-only DNS resolution testing'
        }
    
    def _run_diagnostic(self, result: DiagnosticResult):
        """Execute DNS diagnostics"""
        
        findings = {
            'dns_servers': {},
            'resolution_tests': {},
            'performance_analysis': {},
            'issues_found': [],
            'recommendations': []
        }
        
        # Step 1: Identify current DNS configuration
        self.logger.info("Checking DNS configuration...")
        current_dns = self.get_system_dns_servers()
        findings['current_dns_config'] = current_dns
        
        # Step 2: Test DNS resolution
        self.logger.info("Testing DNS resolution...")
        resolution_results = self.test_dns_resolution(self.test_domains)
        findings['resolution_tests'] = resolution_results
        
        # Step 3: Test DNS server responsiveness
        self.logger.info("Testing DNS server performance...")
        dns_performance = self.test_dns_servers_performance()
        findings['dns_servers'] = dns_performance
        
        # Step 4: Analyze results and identify issues
        self._analyze_results(findings)
        
        # Set overall result status
        if any(issue['severity'] == 'critical' for issue in findings['issues_found']):
            result.complete({'status': 'critical', 'findings': findings})
            result.add_warning('Critical DNS issues detected')
        elif findings['issues_found']:
            result.complete({'status': 'warning', 'findings': findings})
            result.add_warning('DNS issues detected that may impact connectivity')
        else:
            result.complete({'status': 'healthy', 'findings': findings})
        
        # Add recommendations
        for rec in findings['recommendations']:
            result.add_recommendation(rec)
    
    def get_system_dns_servers(self) -> Dict[str, List[str]]:
        """Wrapper for standalone function"""
        return get_system_dns_servers()
    
    def test_dns_resolution(self, domains: List[str]) -> Dict[str, Dict[str, Any]]:
        """Test DNS resolution for multiple domains"""
        return test_dns_resolution_batch(domains)
    
    def test_dns_servers_performance(self) -> Dict[str, Any]:
        """Test performance of configured and public DNS servers"""
        performance_results = {}
        
        # Test current DNS servers
        current_dns = self.get_system_dns_servers()
        for dns in current_dns.get('all_dns', []):
            result = test_dns_server(dns)
            performance_results[f'Current: {dns}'] = result
        
        # Test public DNS servers for comparison
        for name, dns in self.public_dns_servers.items():
            result = test_dns_server(dns)
            performance_results[name] = result
        
        return performance_results
    
    def _analyze_results(self, findings: Dict[str, Any]):
        """Analyze DNS test results and identify issues"""
        
        # Check resolution failures
        resolution_tests = findings.get('resolution_tests', {})
        failed_resolutions = [domain for domain, result in resolution_tests.items() 
                             if not result.get('resolved', False)]
        
        if len(failed_resolutions) == len(resolution_tests):
            findings['issues_found'].append({
                'severity': 'critical',
                'category': 'dns_failure',
                'issue': 'Complete DNS resolution failure'
            })
            findings['recommendations'].append('Check internet connectivity')
            findings['recommendations'].append('Verify DNS server is reachable')
            findings['recommendations'].append('Try using public DNS servers (8.8.8.8 or 1.1.1.1)')
        elif failed_resolutions:
            findings['issues_found'].append({
                'severity': 'warning',
                'category': 'partial_dns_failure',
                'issue': f'Some domains failed to resolve: {", ".join(failed_resolutions)}'
            })
        
        # Check DNS server performance
        dns_servers = findings.get('dns_servers', {})
        slow_servers = []
        unreachable_servers = []
        
        for server_name, result in dns_servers.items():
            if not result.get('reachable', False):
                unreachable_servers.append(server_name)
            elif result.get('response_time', 0) > 200:  # >200ms is slow
                slow_servers.append((server_name, result['response_time']))
        
        if unreachable_servers:
            findings['issues_found'].append({
                'severity': 'high',
                'category': 'dns_server_unreachable',
                'issue': f'DNS servers unreachable: {", ".join(unreachable_servers)}'
            })
            findings['recommendations'].append('Configure alternative DNS servers')
        
        if slow_servers:
            findings['issues_found'].append({
                'severity': 'medium',
                'category': 'slow_dns',
                'issue': f'Slow DNS servers detected'
            })
            for server, response_time in slow_servers:
                findings['recommendations'].append(
                    f'{server} is slow ({response_time}ms) - consider faster alternatives'
                )
        
        # Compare with public DNS performance
        current_dns_avg = self._calculate_avg_response_time(
            {k: v for k, v in dns_servers.items() if k.startswith('Current:')}
        )
        public_dns_avg = self._calculate_avg_response_time(
            {k: v for k, v in dns_servers.items() if not k.startswith('Current:')}
        )
        
        if current_dns_avg > 0 and public_dns_avg > 0 and current_dns_avg > public_dns_avg * 2:
            findings['recommendations'].append(
                f'Public DNS servers are significantly faster ({public_dns_avg:.0f}ms vs {current_dns_avg:.0f}ms)'
            )
    
    def _calculate_avg_response_time(self, servers: Dict[str, Any]) -> float:
        """Calculate average response time for reachable servers"""
        response_times = [s['response_time'] for s in servers.values() 
                         if s.get('reachable') and s.get('response_time')]
        return sum(response_times) / len(response_times) if response_times else 0


# Standalone DNS diagnostic functions for Claude Code

def resolve_hostname(hostname: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Resolve a hostname and return detailed results
    
    Args:
        hostname: Domain name to resolve
        timeout: Resolution timeout in seconds
        
    Returns:
        Dict with resolution results including IPs, timing, and errors
    """
    result = {
        'hostname': hostname,
        'resolved': False,
        'ip_addresses': [],
        'ipv6_addresses': [],
        'resolution_time': None,
        'error': None
    }
    
    start_time = time.time()
    
    try:
        # Set timeout
        socket.setdefaulttimeout(timeout)
        
        # Try IPv4 resolution
        try:
            ipv4_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            result['ip_addresses'] = list(set([addr[4][0] for addr in ipv4_info]))
            result['resolved'] = True
        except socket.gaierror:
            pass
        
        # Try IPv6 resolution
        try:
            ipv6_info = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            result['ipv6_addresses'] = list(set([addr[4][0] for addr in ipv6_info]))
            result['resolved'] = True
        except socket.gaierror:
            pass
        
        result['resolution_time'] = round((time.time() - start_time) * 1000, 2)  # ms
        
    except socket.timeout:
        result['error'] = 'Resolution timeout'
        result['resolution_time'] = round((time.time() - start_time) * 1000, 2)
    except Exception as e:
        result['error'] = str(e)
        result['resolution_time'] = round((time.time() - start_time) * 1000, 2)
    
    return result


def test_dns_server(dns_server: str, test_domain: str = 'google.com') -> Dict[str, Any]:
    """Test a specific DNS server's responsiveness
    
    Args:
        dns_server: IP address of DNS server to test
        test_domain: Domain to use for testing
        
    Returns:
        Dict with server test results
    """
    result = {
        'server': dns_server,
        'reachable': False,
        'response_time': None,
        'resolved_ip': None,
        'error': None
    }
    
    # Use nslookup or dig depending on platform
    if platform.system() == 'Windows':
        cmd = ['nslookup', test_domain, dns_server]
    else:
        cmd = ['dig', f'@{dns_server}', test_domain, '+short', '+time=2']
    
    start_time = time.time()
    
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        response_time = round((time.time() - start_time) * 1000, 2)  # ms
        
        if process.returncode == 0:
            result['reachable'] = True
            result['response_time'] = response_time
            
            # Parse IP from output
            if platform.system() == 'Windows':
                # Parse nslookup output
                lines = process.stdout.strip().split('\n')
                for line in lines:
                    if 'Address' in line and dns_server not in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            result['resolved_ip'] = ip_match.group(1)
                            break
            else:
                # Parse dig output
                ips = process.stdout.strip().split('\n')
                if ips and ips[0]:
                    result['resolved_ip'] = ips[0]
        else:
            result['error'] = 'DNS server did not respond correctly'
            
    except subprocess.TimeoutExpired:
        result['error'] = 'Request timeout'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_system_dns_servers() -> Dict[str, List[str]]:
    """Get the system's configured DNS servers
    
    Returns:
        Dict with DNS server configuration
    """
    dns_config = {
        'primary_dns': [],
        'all_dns': [],
        'method': None
    }
    
    try:
        if platform.system() == 'Darwin':  # macOS
            # Use scutil to get DNS servers
            cmd = ['scutil', '--dns']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                dns_config['method'] = 'scutil'
                nameserver_pattern = r'nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)'
                matches = re.findall(nameserver_pattern, result.stdout)
                dns_config['all_dns'] = list(set(matches))
                if dns_config['all_dns']:
                    dns_config['primary_dns'] = [dns_config['all_dns'][0]]
                    
        elif platform.system() == 'Linux':
            # Parse /etc/resolv.conf
            dns_config['method'] = '/etc/resolv.conf'
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('nameserver'):
                        ip = line.split()[1]
                        dns_config['all_dns'].append(ip)
                if dns_config['all_dns']:
                    dns_config['primary_dns'] = [dns_config['all_dns'][0]]
                    
        elif platform.system() == 'Windows':
            # Use ipconfig /all
            cmd = ['ipconfig', '/all']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                dns_config['method'] = 'ipconfig'
                dns_pattern = r'DNS Servers.*?:\s*(\d+\.\d+\.\d+\.\d+)'
                matches = re.findall(dns_pattern, result.stdout, re.DOTALL)
                dns_config['all_dns'] = list(set(matches))
                if dns_config['all_dns']:
                    dns_config['primary_dns'] = [dns_config['all_dns'][0]]
                    
    except Exception as e:
        logger.error(f"Failed to get system DNS servers: {str(e)}")
        dns_config['error'] = str(e)
    
    return dns_config


def test_dns_resolution_batch(domains: List[str], timeout: float = 5.0) -> Dict[str, Dict[str, Any]]:
    """Test DNS resolution for multiple domains concurrently
    
    Args:
        domains: List of domains to test
        timeout: Resolution timeout per domain
        
    Returns:
        Dict with resolution results for each domain
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {
            executor.submit(resolve_hostname, domain, timeout): domain 
            for domain in domains
        }
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                results[domain] = {
                    'hostname': domain,
                    'resolved': False,
                    'error': str(e)
                }
    
    return results


def analyze_dns_performance(test_results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze DNS test results and provide insights
    
    Args:
        test_results: Results from DNS tests
        
    Returns:
        Dict with analysis and recommendations
    """
    analysis = {
        'overall_health': 'healthy',
        'issues': [],
        'recommendations': [],
        'statistics': {}
    }
    
    # Calculate resolution success rate
    total_tests = len(test_results)
    successful_resolutions = sum(1 for r in test_results.values() if r.get('resolved', False))
    
    analysis['statistics']['success_rate'] = (successful_resolutions / total_tests * 100) if total_tests > 0 else 0
    
    # Calculate average resolution time
    resolution_times = [r['resolution_time'] for r in test_results.values() 
                       if r.get('resolution_time') is not None]
    
    if resolution_times:
        analysis['statistics']['avg_resolution_time'] = round(sum(resolution_times) / len(resolution_times), 2)
        analysis['statistics']['max_resolution_time'] = max(resolution_times)
        analysis['statistics']['min_resolution_time'] = min(resolution_times)
    
    # Identify issues
    if analysis['statistics']['success_rate'] < 50:
        analysis['overall_health'] = 'critical'
        analysis['issues'].append('More than 50% of DNS resolutions are failing')
        analysis['recommendations'].append('Check internet connectivity and DNS server configuration')
    elif analysis['statistics']['success_rate'] < 90:
        analysis['overall_health'] = 'warning'
        analysis['issues'].append('Some DNS resolutions are failing')
        analysis['recommendations'].append('Consider using alternative DNS servers like 8.8.8.8 or 1.1.1.1')
    
    if resolution_times and analysis['statistics']['avg_resolution_time'] > 500:
        analysis['overall_health'] = 'warning'
        analysis['issues'].append('DNS resolution is slow (>500ms average)')
        analysis['recommendations'].append('Consider using a faster DNS server or checking network latency')
    
    return analysis


def diagnose_dns_issue(symptom: str) -> Dict[str, Any]:
    """Diagnose specific DNS issues based on symptoms
    
    This function helps Claude Code diagnose DNS issues based on
    user-reported symptoms.
    
    Args:
        symptom: Description of the DNS issue
        
    Returns:
        Dict with diagnostic results and recommendations
    """
    diagnosis = {
        'symptom': symptom,
        'tests_performed': [],
        'findings': {},
        'likely_cause': None,
        'recommendations': []
    }
    
    # Common symptoms and their diagnostic approach
    if 'slow' in symptom.lower() or 'timeout' in symptom.lower():
        # Test DNS server performance
        diagnosis['tests_performed'].append('DNS server performance test')
        
        dns_servers = get_system_dns_servers()
        if dns_servers.get('primary_dns'):
            for dns in dns_servers['primary_dns']:
                result = test_dns_server(dns)
                diagnosis['findings'][f'DNS {dns}'] = result
                
                if result.get('response_time', float('inf')) > 100:
                    diagnosis['likely_cause'] = 'Slow DNS server response'
                    diagnosis['recommendations'].append(f'DNS server {dns} is slow, consider switching to 8.8.8.8 or 1.1.1.1')
    
    elif 'fail' in symptom.lower() or 'resolve' in symptom.lower():
        # Test basic resolution
        diagnosis['tests_performed'].append('Basic DNS resolution test')
        
        test_results = test_dns_resolution_batch(['google.com', 'cloudflare.com'])
        diagnosis['findings']['resolution_tests'] = test_results
        
        if all(not r.get('resolved', False) for r in test_results.values()):
            diagnosis['likely_cause'] = 'Complete DNS failure'
            diagnosis['recommendations'].append('Check internet connectivity')
            diagnosis['recommendations'].append('Verify DNS server configuration')
            diagnosis['recommendations'].append('Try flushing DNS cache')
    
    elif 'specific' in symptom.lower() or 'some' in symptom.lower():
        # Selective DNS issues
        diagnosis['tests_performed'].append('Multiple DNS server comparison')
        diagnosis['likely_cause'] = 'Selective DNS resolution issues'
        diagnosis['recommendations'].append('Test with public DNS servers to isolate the issue')
        diagnosis['recommendations'].append('Check for DNS filtering or blocking')
    
    return diagnosis


# Demo function
def run_dns_diagnostics():
    """Run comprehensive DNS diagnostics"""
    
    print("\n🔍 DNS DIAGNOSTICS")
    print("=" * 50)
    
    # Get current DNS configuration
    print("\n📋 Current DNS Configuration:")
    dns_config = get_system_dns_servers()
    print(f"   Primary DNS: {dns_config.get('primary_dns', ['Not found'])}")
    print(f"   All DNS servers: {dns_config.get('all_dns', [])}")
    
    # Test resolution
    print("\n🌐 Testing DNS Resolution:")
    test_domains = ['google.com', 'github.com', 'badexample.invalid']
    results = test_dns_resolution_batch(test_domains)
    
    for domain, result in results.items():
        if result['resolved']:
            print(f"   ✅ {domain}: {result['resolution_time']}ms")
            if result['ip_addresses']:
                print(f"      IPv4: {', '.join(result['ip_addresses'])}")
        else:
            print(f"   ❌ {domain}: {result.get('error', 'Failed')}")
    
    # Analyze performance
    print("\n📊 DNS Performance Analysis:")
    analysis = analyze_dns_performance(results)
    print(f"   Overall Health: {analysis['overall_health'].upper()}")
    print(f"   Success Rate: {analysis['statistics']['success_rate']:.1f}%")
    if 'avg_resolution_time' in analysis['statistics']:
        print(f"   Avg Resolution Time: {analysis['statistics']['avg_resolution_time']}ms")
    
    if analysis['recommendations']:
        print("\n💡 Recommendations:")
        for rec in analysis['recommendations']:
            print(f"   • {rec}")
    
    return results


if __name__ == "__main__":
    run_dns_diagnostics()