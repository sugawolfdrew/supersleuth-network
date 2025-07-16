"""
Performance analysis and SLA monitoring module
"""

import time
import statistics
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import threading
import queue

from ..core.diagnostic import BaseDiagnostic, DiagnosticResult
from ..core.authorization import AuthorizationRequest, RiskLevel
from ..utils.logger import get_logger


class PerformanceAnalysis(BaseDiagnostic):
    """Enterprise-grade network performance analysis with SLA validation"""
    
    def __init__(self, config: Dict, sla_thresholds: Optional[Dict] = None):
        super().__init__(config)
        self.sla_thresholds = sla_thresholds or self._default_sla_thresholds()
        self.test_duration = config.get('test_duration', 60)  # seconds
        self.test_interval = config.get('test_interval', 5)   # seconds between tests
        self.results_queue = queue.Queue()
        
    def _default_sla_thresholds(self) -> Dict[str, Any]:
        """Default SLA thresholds for enterprise networks"""
        return {
            'min_download_mbps': 100,
            'min_upload_mbps': 50,
            'max_latency_ms': 50,
            'max_jitter_ms': 10,
            'max_packet_loss_percent': 0.1,
            'voip_mos_score': 4.0,  # Mean Opinion Score for VoIP
            'video_conf_bandwidth_mbps': 10
        }
    
    def validate_prerequisites(self) -> bool:
        """Check if prerequisites are met"""
        
        # Check for required tools
        required_tools = ['ping', 'speedtest-cli']
        optional_tools = ['iperf3', 'netperf']
        
        for tool in required_tools:
            if not self._check_tool_available(tool):
                self.logger.error(f"Required tool '{tool}' not available")
                return False
        
        # Log optional tools status
        for tool in optional_tools:
            if self._check_tool_available(tool):
                self.logger.info(f"Optional tool '{tool}' available for advanced testing")
        
        return True
    
    def get_authorization_required(self) -> Dict[str, Any]:
        """Return authorization requirements"""
        return {
            'read_only': False,
            'system_changes': False,
            'data_access': 'network_performance_testing',
            'risk_level': RiskLevel.MEDIUM.value,
            'requires_approval': True,
            'business_impact': 'Temporary bandwidth utilization during testing'
        }
    
    def run(self) -> DiagnosticResult:
        """Execute performance analysis"""
        
        result = DiagnosticResult("Performance Analysis")
        
        try:
            self.logger.info("Starting performance analysis")
            
            # Run various performance tests
            performance_data = {
                'timestamp': datetime.now().isoformat(),
                'test_duration': self.test_duration,
                'connectivity': self._test_connectivity(),
                'bandwidth': self._test_bandwidth(),
                'latency': self._test_latency(),
                'jitter': self._test_jitter(),
                'packet_loss': self._test_packet_loss(),
                'dns_performance': self._test_dns_performance(),
                'application_specific': self._test_application_performance()
            }
            
            # Validate against SLA
            sla_validation = self._validate_sla(performance_data)
            
            # Analyze trends if historical data available
            trend_analysis = self._analyze_performance_trends(performance_data)
            
            # Complete result
            result.complete({
                'performance_metrics': performance_data,
                'sla_validation': sla_validation,
                'trend_analysis': trend_analysis,
                'overall_score': self._calculate_performance_score(performance_data, sla_validation)
            })
            
            # Add recommendations based on findings
            self._add_performance_recommendations(result, performance_data, sla_validation)
            
        except Exception as e:
            self.logger.error(f"Performance analysis failed: {str(e)}")
            result.fail(str(e))
        
        return result
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _test_connectivity(self) -> Dict[str, Any]:
        """Test basic connectivity to various targets"""
        
        self.logger.info("Testing connectivity...")
        
        targets = [
            {'name': 'Gateway', 'host': self._get_default_gateway(), 'critical': True},
            {'name': 'DNS Server', 'host': self._get_dns_server(), 'critical': True},
            {'name': 'Internet (Google)', 'host': '8.8.8.8', 'critical': True},
            {'name': 'CloudFlare', 'host': '1.1.1.1', 'critical': False},
            {'name': 'Microsoft 365', 'host': 'outlook.office365.com', 'critical': False}
        ]
        
        results = []
        for target in targets:
            if target['host']:
                result = self._ping_host(target['host'], count=10)
                result['target'] = target['name']
                result['critical'] = target['critical']
                results.append(result)
        
        return {
            'targets_tested': len(results),
            'targets_reachable': sum(1 for r in results if r['reachable']),
            'critical_failures': [r for r in results if r['critical'] and not r['reachable']],
            'detailed_results': results
        }
    
    def _test_bandwidth(self) -> Dict[str, Any]:
        """Test bandwidth using speedtest-cli"""
        
        self.logger.info("Testing bandwidth...")
        
        try:
            # Run speedtest
            cmd = ['speedtest-cli', '--json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {
                    'download_mbps': round(data['download'] / 1_000_000, 2),
                    'upload_mbps': round(data['upload'] / 1_000_000, 2),
                    'ping_ms': data['ping'],
                    'server': data['server']['sponsor'],
                    'server_location': f"{data['server']['name']}, {data['server']['country']}",
                    'test_timestamp': data['timestamp']
                }
            else:
                self.logger.warning(f"Speedtest failed: {result.stderr}")
                return self._fallback_bandwidth_test()
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Speedtest timed out")
            return self._fallback_bandwidth_test()
        except Exception as e:
            self.logger.error(f"Bandwidth test error: {str(e)}")
            return {'error': str(e)}
    
    def _fallback_bandwidth_test(self) -> Dict[str, Any]:
        """Fallback bandwidth test using curl"""
        
        self.logger.info("Running fallback bandwidth test...")
        
        # Test download speed using a CDN test file
        test_urls = [
            'http://speedtest.ftp.otenet.gr/files/test10Mb.db',
            'http://download.thinkbroadband.com/10MB.zip'
        ]
        
        for url in test_urls:
            try:
                start_time = time.time()
                cmd = ['curl', '-o', '/dev/null', '-s', '-w', '%{size_download}', url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    duration = time.time() - start_time
                    bytes_downloaded = int(result.stdout)
                    mbps = (bytes_downloaded * 8) / (duration * 1_000_000)
                    
                    return {
                        'download_mbps': round(mbps, 2),
                        'upload_mbps': None,  # Can't test upload with curl
                        'test_method': 'curl_fallback',
                        'test_file_size_mb': round(bytes_downloaded / 1_000_000, 2)
                    }
            except:
                continue
        
        return {'error': 'All bandwidth tests failed'}
    
    def _test_latency(self) -> Dict[str, Any]:
        """Test latency to various endpoints"""
        
        self.logger.info("Testing latency...")
        
        endpoints = {
            'local_gateway': self._get_default_gateway(),
            'public_dns': '8.8.8.8',
            'regional_server': self._get_regional_server(),
            'application_server': self.config.get('app_server', 'example.com')
        }
        
        latency_results = {}
        for name, host in endpoints.items():
            if host:
                ping_result = self._ping_host(host, count=20)
                if ping_result['reachable']:
                    latency_results[name] = {
                        'min_ms': ping_result['min_ms'],
                        'avg_ms': ping_result['avg_ms'],
                        'max_ms': ping_result['max_ms'],
                        'mdev_ms': ping_result.get('mdev_ms', 0)
                    }
        
        return latency_results
    
    def _test_jitter(self) -> Dict[str, Any]:
        """Test network jitter"""
        
        self.logger.info("Testing jitter...")
        
        # Jitter test by sending rapid pings
        target = self.config.get('jitter_test_target', '8.8.8.8')
        ping_count = 50
        
        ping_result = self._ping_host(target, count=ping_count, interval=0.1)
        
        if ping_result['reachable'] and 'rtts' in ping_result:
            rtts = ping_result['rtts']
            
            # Calculate jitter (variation in latency)
            jitter_values = []
            for i in range(1, len(rtts)):
                jitter_values.append(abs(rtts[i] - rtts[i-1]))
            
            return {
                'avg_jitter_ms': round(statistics.mean(jitter_values), 2),
                'max_jitter_ms': round(max(jitter_values), 2),
                'jitter_std_dev': round(statistics.stdev(jitter_values), 2) if len(jitter_values) > 1 else 0,
                'samples': len(jitter_values)
            }
        
        return {'error': 'Jitter test failed'}
    
    def _test_packet_loss(self) -> Dict[str, Any]:
        """Test packet loss to various destinations"""
        
        self.logger.info("Testing packet loss...")
        
        destinations = {
            'gateway': self._get_default_gateway(),
            'internet': '8.8.8.8',
            'application': self.config.get('app_server', 'example.com')
        }
        
        packet_loss_results = {}
        
        for name, host in destinations.items():
            if host:
                # Send 100 packets for accurate loss measurement
                ping_result = self._ping_host(host, count=100)
                
                if 'packet_loss_percent' in ping_result:
                    packet_loss_results[name] = {
                        'loss_percent': ping_result['packet_loss_percent'],
                        'packets_sent': ping_result.get('packets_sent', 100),
                        'packets_received': ping_result.get('packets_received', 0)
                    }
        
        return packet_loss_results
    
    def _test_dns_performance(self) -> Dict[str, Any]:
        """Test DNS resolution performance"""
        
        self.logger.info("Testing DNS performance...")
        
        test_domains = [
            'google.com',
            'microsoft.com',
            'cloudflare.com',
            self.config.get('client_domain', 'example.com')
        ]
        
        dns_servers = [
            {'name': 'System DNS', 'server': None},
            {'name': 'Google DNS', 'server': '8.8.8.8'},
            {'name': 'Cloudflare DNS', 'server': '1.1.1.1'}
        ]
        
        results = {}
        
        for dns in dns_servers:
            server_results = []
            
            for domain in test_domains:
                start_time = time.time()
                
                if dns['server']:
                    cmd = ['nslookup', domain, dns['server']]
                else:
                    cmd = ['nslookup', domain]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    resolution_time = (time.time() - start_time) * 1000  # Convert to ms
                    
                    server_results.append({
                        'domain': domain,
                        'resolved': result.returncode == 0,
                        'time_ms': round(resolution_time, 2)
                    })
                except subprocess.TimeoutExpired:
                    server_results.append({
                        'domain': domain,
                        'resolved': False,
                        'time_ms': 5000  # Timeout value
                    })
            
            # Calculate statistics
            successful_lookups = [r['time_ms'] for r in server_results if r['resolved']]
            
            results[dns['name']] = {
                'avg_resolution_ms': round(statistics.mean(successful_lookups), 2) if successful_lookups else None,
                'max_resolution_ms': max(successful_lookups) if successful_lookups else None,
                'success_rate': len(successful_lookups) / len(test_domains) * 100,
                'details': server_results
            }
        
        return results
    
    def _test_application_performance(self) -> Dict[str, Any]:
        """Test performance for specific applications"""
        
        self.logger.info("Testing application-specific performance...")
        
        results = {}
        
        # VoIP simulation
        voip_result = self._simulate_voip_test()
        if voip_result:
            results['voip'] = voip_result
        
        # Video conferencing simulation
        video_result = self._simulate_video_conference_test()
        if video_result:
            results['video_conferencing'] = video_result
        
        # File transfer simulation
        file_transfer_result = self._simulate_file_transfer()
        if file_transfer_result:
            results['file_transfer'] = file_transfer_result
        
        return results
    
    def _simulate_voip_test(self) -> Optional[Dict[str, Any]]:
        """Simulate VoIP performance test"""
        
        # Use ping to simulate VoIP packets (small, frequent)
        voip_server = self.config.get('voip_server', '8.8.8.8')
        
        ping_result = self._ping_host(
            voip_server, 
            count=100, 
            packet_size=160,  # Typical VoIP packet size
            interval=0.02     # 50 packets per second
        )
        
        if ping_result['reachable']:
            # Calculate MOS score based on latency, jitter, and packet loss
            mos_score = self._calculate_mos_score(
                ping_result['avg_ms'],
                ping_result.get('mdev_ms', 0),
                ping_result['packet_loss_percent']
            )
            
            return {
                'mos_score': mos_score,
                'quality': self._mos_to_quality(mos_score),
                'latency_ms': ping_result['avg_ms'],
                'jitter_ms': ping_result.get('mdev_ms', 0),
                'packet_loss_percent': ping_result['packet_loss_percent']
            }
        
        return None
    
    def _calculate_mos_score(self, latency_ms: float, jitter_ms: float, loss_percent: float) -> float:
        """Calculate Mean Opinion Score for VoIP quality"""
        
        # Simplified E-model calculation
        # R = 93.2 - Id - Ie
        
        # Delay impairment
        if latency_ms < 150:
            Id = 0.024 * latency_ms
        else:
            Id = 0.024 * 150 + 0.11 * (latency_ms - 150)
        
        # Equipment impairment (packet loss and jitter)
        Ie = loss_percent * 2.5 + jitter_ms * 0.5
        
        R = 93.2 - Id - Ie
        
        # Convert R-value to MOS
        if R < 0:
            mos = 1.0
        elif R > 100:
            mos = 4.5
        else:
            mos = 1 + 0.035 * R + 0.000007 * R * (R - 60) * (100 - R)
        
        return round(mos, 1)
    
    def _mos_to_quality(self, mos: float) -> str:
        """Convert MOS score to quality description"""
        
        if mos >= 4.3:
            return "Excellent"
        elif mos >= 4.0:
            return "Good"
        elif mos >= 3.6:
            return "Fair"
        elif mos >= 3.1:
            return "Poor"
        else:
            return "Bad"
    
    def _simulate_video_conference_test(self) -> Optional[Dict[str, Any]]:
        """Simulate video conferencing performance"""
        
        # Test sustained bandwidth and latency
        video_server = self.config.get('video_server', 'example.com')
        
        # Quick bandwidth check
        bandwidth = self._quick_bandwidth_check()
        
        # Latency and jitter check
        ping_result = self._ping_host(video_server, count=30, packet_size=1200)
        
        if ping_result['reachable'] and bandwidth:
            quality_metrics = {
                'bandwidth_available_mbps': bandwidth,
                'latency_ms': ping_result['avg_ms'],
                'jitter_ms': ping_result.get('mdev_ms', 0),
                'packet_loss_percent': ping_result['packet_loss_percent']
            }
            
            # Determine video quality possible
            if bandwidth >= 15 and ping_result['avg_ms'] < 150:
                quality_metrics['max_quality'] = '1080p HD'
                quality_metrics['quality_rating'] = 'Excellent'
            elif bandwidth >= 5 and ping_result['avg_ms'] < 200:
                quality_metrics['max_quality'] = '720p HD'
                quality_metrics['quality_rating'] = 'Good'
            elif bandwidth >= 1.5 and ping_result['avg_ms'] < 300:
                quality_metrics['max_quality'] = '480p SD'
                quality_metrics['quality_rating'] = 'Fair'
            else:
                quality_metrics['max_quality'] = 'Audio only'
                quality_metrics['quality_rating'] = 'Poor'
            
            return quality_metrics
        
        return None
    
    def _simulate_file_transfer(self) -> Optional[Dict[str, Any]]:
        """Simulate file transfer performance"""
        
        # Download a test file and measure throughput
        test_url = 'http://speedtest.ftp.otenet.gr/files/test1Mb.db'
        
        try:
            start_time = time.time()
            cmd = ['curl', '-o', '/dev/null', '-s', '-w', '%{size_download}\\n%{speed_download}', test_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                size_bytes = int(lines[0])
                speed_bps = float(lines[1])
                duration = time.time() - start_time
                
                return {
                    'throughput_mbps': round(speed_bps * 8 / 1_000_000, 2),
                    'file_size_mb': round(size_bytes / 1_000_000, 2),
                    'transfer_time_sec': round(duration, 2),
                    'efficiency_percent': round((speed_bps * 8) / (self.sla_thresholds['min_download_mbps'] * 1_000_000) * 100, 1)
                }
        except:
            pass
        
        return None
    
    def _quick_bandwidth_check(self) -> Optional[float]:
        """Quick bandwidth check for simulations"""
        
        # Use a small file for quick check
        test_url = 'http://speedtest.ftp.otenet.gr/files/test1Mb.db'
        
        try:
            start_time = time.time()
            cmd = ['curl', '-o', '/dev/null', '-s', test_url]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            
            if result.returncode == 0:
                duration = time.time() - start_time
                # 1MB file, convert to Mbps
                mbps = (1 * 8) / duration
                return round(mbps, 2)
        except:
            pass
        
        return None
    
    def _ping_host(self, host: str, count: int = 10, packet_size: int = 56, 
                   interval: float = 1.0) -> Dict[str, Any]:
        """Ping a host and return statistics"""
        
        try:
            # Build ping command based on OS
            import platform
            if platform.system() == "Darwin":  # macOS
                cmd = ['ping', '-c', str(count), '-i', str(interval), '-s', str(packet_size), host]
            else:  # Linux
                cmd = ['ping', '-c', str(count), '-i', str(interval), '-s', str(packet_size), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * interval + 5)
            
            if result.returncode == 0:
                # Parse ping output
                return self._parse_ping_output(result.stdout)
            else:
                return {
                    'reachable': False,
                    'error': 'Host unreachable'
                }
                
        except subprocess.TimeoutExpired:
            return {
                'reachable': False,
                'error': 'Ping timeout'
            }
        except Exception as e:
            return {
                'reachable': False,
                'error': str(e)
            }
    
    def _parse_ping_output(self, output: str) -> Dict[str, Any]:
        """Parse ping command output"""
        
        lines = output.strip().split('\n')
        stats = {'reachable': True, 'rtts': []}
        
        # Extract RTT values
        for line in lines:
            if 'time=' in line:
                try:
                    time_str = line.split('time=')[1].split()[0]
                    stats['rtts'].append(float(time_str))
                except:
                    continue
        
        # Parse statistics line
        for line in lines:
            if 'packet loss' in line:
                # Extract packet loss percentage
                try:
                    loss_str = line.split('%')[0].split()[-1]
                    stats['packet_loss_percent'] = float(loss_str)
                except:
                    stats['packet_loss_percent'] = 0.0
                
                # Extract sent/received packets
                parts = line.split(',')
                for part in parts:
                    if 'packets transmitted' in part:
                        stats['packets_sent'] = int(part.split()[0])
                    elif 'received' in part:
                        stats['packets_received'] = int(part.split()[0])
            
            elif 'min/avg/max' in line:
                # Parse RTT statistics
                try:
                    values = line.split('=')[1].strip().split('/')
                    stats['min_ms'] = float(values[0])
                    stats['avg_ms'] = float(values[1])
                    stats['max_ms'] = float(values[2])
                    if len(values) > 3:
                        stats['mdev_ms'] = float(values[3])
                except:
                    pass
        
        # Calculate statistics if not provided
        if stats['rtts'] and 'avg_ms' not in stats:
            stats['min_ms'] = min(stats['rtts'])
            stats['avg_ms'] = statistics.mean(stats['rtts'])
            stats['max_ms'] = max(stats['rtts'])
            stats['mdev_ms'] = statistics.stdev(stats['rtts']) if len(stats['rtts']) > 1 else 0
        
        return stats
    
    def _get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        
        try:
            import platform
            if platform.system() == "Darwin":  # macOS
                cmd = ['netstat', '-nr']
            else:  # Linux
                cmd = ['ip', 'route', 'show', 'default']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'default' in line:
                        parts = line.split()
                        # Find IP address in the line
                        for part in parts:
                            if '.' in part and part.count('.') == 3:
                                return part
        except:
            pass
        
        return None
    
    def _get_dns_server(self) -> Optional[str]:
        """Get primary DNS server"""
        
        try:
            # Try to read from resolv.conf
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        return line.split()[1]
        except:
            pass
        
        # Fallback to common DNS
        return '8.8.8.8'
    
    def _get_regional_server(self) -> Optional[str]:
        """Get a regional server for latency testing"""
        
        # This would ideally use geolocation
        # For now, return a CDN endpoint
        return 'www.cloudflare.com'
    
    def _validate_sla(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate performance against SLA thresholds"""
        
        validation_results = {
            'compliant': True,
            'violations': [],
            'warnings': [],
            'detailed_checks': {}
        }
        
        # Check bandwidth
        if 'bandwidth' in performance_data and 'download_mbps' in performance_data['bandwidth']:
            download_mbps = performance_data['bandwidth']['download_mbps']
            if download_mbps < self.sla_thresholds['min_download_mbps']:
                validation_results['violations'].append({
                    'metric': 'download_bandwidth',
                    'threshold': self.sla_thresholds['min_download_mbps'],
                    'actual': download_mbps,
                    'severity': 'high'
                })
                validation_results['compliant'] = False
            
            validation_results['detailed_checks']['bandwidth'] = {
                'download': download_mbps >= self.sla_thresholds['min_download_mbps'],
                'upload': performance_data['bandwidth'].get('upload_mbps', 0) >= self.sla_thresholds['min_upload_mbps']
            }
        
        # Check latency
        if 'latency' in performance_data:
            for endpoint, metrics in performance_data['latency'].items():
                if metrics['avg_ms'] > self.sla_thresholds['max_latency_ms']:
                    validation_results['warnings'].append({
                        'metric': f'latency_{endpoint}',
                        'threshold': self.sla_thresholds['max_latency_ms'],
                        'actual': metrics['avg_ms'],
                        'severity': 'medium'
                    })
        
        # Check packet loss
        if 'packet_loss' in performance_data:
            for destination, loss_data in performance_data['packet_loss'].items():
                if loss_data['loss_percent'] > self.sla_thresholds['max_packet_loss_percent']:
                    validation_results['violations'].append({
                        'metric': f'packet_loss_{destination}',
                        'threshold': self.sla_thresholds['max_packet_loss_percent'],
                        'actual': loss_data['loss_percent'],
                        'severity': 'high'
                    })
                    validation_results['compliant'] = False
        
        # Check VoIP quality
        if 'application_specific' in performance_data and 'voip' in performance_data['application_specific']:
            voip_data = performance_data['application_specific']['voip']
            if voip_data['mos_score'] < self.sla_thresholds['voip_mos_score']:
                validation_results['violations'].append({
                    'metric': 'voip_quality',
                    'threshold': self.sla_thresholds['voip_mos_score'],
                    'actual': voip_data['mos_score'],
                    'severity': 'high'
                })
                validation_results['compliant'] = False
        
        return validation_results
    
    def _analyze_performance_trends(self, current_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze performance trends if historical data available"""
        
        # In a real implementation, this would query historical data
        # For now, return placeholder analysis
        
        return {
            'trend_available': False,
            'message': 'Historical data not available for trend analysis',
            'recommendation': 'Enable continuous monitoring to build performance baseline'
        }
    
    def _calculate_performance_score(self, performance_data: Dict[str, Any], 
                                   sla_validation: Dict[str, Any]) -> int:
        """Calculate overall performance score (0-100)"""
        
        score = 100
        
        # Deduct points for SLA violations
        for violation in sla_validation.get('violations', []):
            if violation['severity'] == 'high':
                score -= 15
            elif violation['severity'] == 'medium':
                score -= 10
            else:
                score -= 5
        
        # Deduct points for warnings
        for warning in sla_validation.get('warnings', []):
            score -= 3
        
        # Ensure score doesn't go below 0
        return max(0, score)
    
    def _add_performance_recommendations(self, result: DiagnosticResult, 
                                       performance_data: Dict[str, Any],
                                       sla_validation: Dict[str, Any]):
        """Add recommendations based on performance analysis"""
        
        # Bandwidth recommendations
        if 'bandwidth' in performance_data:
            bandwidth = performance_data['bandwidth']
            if 'download_mbps' in bandwidth:
                if bandwidth['download_mbps'] < self.sla_thresholds['min_download_mbps']:
                    result.add_recommendation(
                        f"Upgrade internet connection - current {bandwidth['download_mbps']} Mbps "
                        f"is below SLA requirement of {self.sla_thresholds['min_download_mbps']} Mbps"
                    )
        
        # Latency recommendations
        high_latency_endpoints = []
        if 'latency' in performance_data:
            for endpoint, metrics in performance_data['latency'].items():
                if metrics['avg_ms'] > self.sla_thresholds['max_latency_ms']:
                    high_latency_endpoints.append(endpoint)
        
        if high_latency_endpoints:
            result.add_recommendation(
                f"Investigate high latency to: {', '.join(high_latency_endpoints)}. "
                "Consider QoS configuration or routing optimization"
            )
        
        # Packet loss recommendations
        if 'packet_loss' in performance_data:
            total_loss = sum(
                loss_data['loss_percent'] 
                for loss_data in performance_data['packet_loss'].values()
            ) / len(performance_data['packet_loss'])
            
            if total_loss > 0.1:
                result.add_recommendation(
                    "Packet loss detected - check for faulty cables, network congestion, "
                    "or interference on wireless connections"
                )
        
        # VoIP recommendations
        if 'application_specific' in performance_data and 'voip' in performance_data['application_specific']:
            voip_data = performance_data['application_specific']['voip']
            if voip_data['mos_score'] < self.sla_thresholds['voip_mos_score']:
                result.add_recommendation(
                    f"VoIP quality below acceptable threshold (MOS: {voip_data['mos_score']}). "
                    "Implement QoS prioritization for voice traffic"
                )
        
        # General optimization
        if not sla_validation['compliant']:
            result.add_recommendation(
                "Consider implementing SD-WAN or MPLS for better performance management "
                "and SLA compliance"
            )