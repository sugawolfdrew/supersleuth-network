"""
Advanced Diagnostics Module for SuperSleuth Network

This module provides deeper system insights and advanced diagnostic capabilities:
- Process analysis and resource monitoring
- System bottleneck detection
- Historical trend analysis
- Anomaly detection

Designed for use by Claude Code to diagnose complex system issues.
"""

import psutil
import time
import json
import statistics
import platform
import socket
from typing import Dict, List, Tuple, Optional, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import os


class AdvancedDiagnostics:
    """Advanced system diagnostics with historical tracking and anomaly detection"""
    
    def __init__(self, history_size: int = 100, anomaly_threshold: float = 2.5):
        """
        Initialize Advanced Diagnostics
        
        Args:
            history_size: Number of historical snapshots to maintain
            anomaly_threshold: Standard deviations for anomaly detection
        """
        self.history_size = history_size
        self.anomaly_threshold = anomaly_threshold
        self.metric_history = defaultdict(lambda: deque(maxlen=history_size))
        self.baseline_metrics = {}
        self.last_snapshot_time = None
        self._lock = threading.Lock()
        
    def process_analysis(self, top_n: int = 10, include_children: bool = True) -> Dict[str, Any]:
        """
        Identify resource-intensive processes
        
        Args:
            top_n: Number of top processes to return
            include_children: Include child processes in analysis
            
        Returns:
            Dictionary containing process analysis results
        """
        try:
            processes = []
            connections_by_pid = defaultdict(list)
            
            # Gather all process information
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                           'memory_info', 'num_threads', 'create_time']):
                try:
                    info = proc.info
                    
                    # Get CPU usage (requires a small delay for accurate measurement)
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    
                    # Get memory info
                    memory_info = proc.memory_info()
                    
                    # Get network connections
                    try:
                        connections = proc.connections(kind='inet')
                        for conn in connections:
                            connections_by_pid[info['pid']].append({
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status,
                                'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                            })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Get IO counters if available
                    io_counters = None
                    try:
                        io_counters = proc.io_counters()
                    except (psutil.AccessDenied, AttributeError):
                        pass
                    
                    process_info = {
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu_percent': cpu_percent,
                        'memory_percent': info['memory_percent'],
                        'memory_rss_mb': memory_info.rss / 1024 / 1024,
                        'memory_vms_mb': memory_info.vms / 1024 / 1024,
                        'num_threads': info['num_threads'],
                        'create_time': datetime.fromtimestamp(info['create_time']).isoformat(),
                        'connections': connections_by_pid[info['pid']],
                        'io_read_mb': io_counters.read_bytes / 1024 / 1024 if io_counters else None,
                        'io_write_mb': io_counters.write_bytes / 1024 / 1024 if io_counters else None
                    }
                    
                    # Get parent/child relationships
                    try:
                        parent = proc.parent()
                        process_info['parent_pid'] = parent.pid if parent else None
                        process_info['parent_name'] = parent.name() if parent else None
                        
                        if include_children:
                            children = proc.children(recursive=True)
                            process_info['num_children'] = len(children)
                            process_info['children_pids'] = [child.pid for child in children]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        process_info['parent_pid'] = None
                        process_info['num_children'] = 0
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by different metrics
            top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:top_n]
            top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:top_n]
            top_connections = sorted(processes, key=lambda x: len(x['connections']), reverse=True)[:top_n]
            
            # Calculate totals
            total_cpu = sum(p['cpu_percent'] for p in processes)
            total_memory = sum(p['memory_percent'] for p in processes)
            
            # Identify process trees consuming most resources
            process_trees = self._analyze_process_trees(processes)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'total_processes': len(processes),
                'total_cpu_percent': round(total_cpu, 2),
                'total_memory_percent': round(total_memory, 2),
                'top_cpu_consumers': top_cpu,
                'top_memory_consumers': top_memory,
                'top_network_users': top_connections,
                'process_trees': process_trees,
                'system_info': {
                    'cpu_count': psutil.cpu_count(),
                    'total_memory_gb': psutil.virtual_memory().total / 1024 / 1024 / 1024
                }
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def system_bottleneck_detection(self) -> Dict[str, Any]:
        """
        Highlight potential performance bottlenecks
        
        Returns:
            Dictionary containing detected bottlenecks and recommendations
        """
        bottlenecks = []
        metrics = {}
        
        try:
            # CPU bottleneck detection
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            avg_cpu = statistics.mean(cpu_percent)
            metrics['cpu'] = {
                'average_percent': round(avg_cpu, 2),
                'per_core': cpu_percent,
                'count': psutil.cpu_count()
            }
            
            if avg_cpu > 80:
                bottlenecks.append({
                    'type': 'cpu',
                    'severity': 'high' if avg_cpu > 90 else 'medium',
                    'value': avg_cpu,
                    'message': f'High CPU usage detected: {avg_cpu:.1f}%',
                    'recommendation': 'Identify and optimize CPU-intensive processes'
                })
            
            # Memory bottleneck detection
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            metrics['memory'] = {
                'percent_used': memory.percent,
                'available_gb': round(memory.available / 1024 / 1024 / 1024, 2),
                'total_gb': round(memory.total / 1024 / 1024 / 1024, 2),
                'swap_percent': swap.percent
            }
            
            if memory.percent > 85:
                bottlenecks.append({
                    'type': 'memory',
                    'severity': 'high' if memory.percent > 95 else 'medium',
                    'value': memory.percent,
                    'message': f'High memory usage: {memory.percent:.1f}%',
                    'recommendation': 'Consider closing unused applications or adding more RAM'
                })
            
            if swap.percent > 50:
                bottlenecks.append({
                    'type': 'swap',
                    'severity': 'medium',
                    'value': swap.percent,
                    'message': f'High swap usage: {swap.percent:.1f}%',
                    'recommendation': 'System is using swap heavily, performance may be degraded'
                })
            
            # Disk I/O bottleneck detection
            disk_io = psutil.disk_io_counters()
            disk_usage = psutil.disk_usage('/')
            
            # Calculate disk I/O rates (if we have previous snapshot)
            io_rates = self._calculate_io_rates(disk_io)
            
            metrics['disk'] = {
                'usage_percent': disk_usage.percent,
                'read_mb_s': io_rates.get('read_mb_s', 0),
                'write_mb_s': io_rates.get('write_mb_s', 0),
                'busy_time_percent': io_rates.get('busy_percent', 0)
            }
            
            if disk_usage.percent > 90:
                bottlenecks.append({
                    'type': 'disk_space',
                    'severity': 'high',
                    'value': disk_usage.percent,
                    'message': f'Low disk space: {disk_usage.percent:.1f}% used',
                    'recommendation': 'Free up disk space to prevent system issues'
                })
            
            if io_rates.get('busy_percent', 0) > 80:
                bottlenecks.append({
                    'type': 'disk_io',
                    'severity': 'medium',
                    'value': io_rates.get('busy_percent', 0),
                    'message': 'High disk I/O activity detected',
                    'recommendation': 'Check for processes doing heavy disk operations'
                })
            
            # Network bottleneck detection
            net_io = psutil.net_io_counters()
            net_rates = self._calculate_network_rates(net_io)
            
            metrics['network'] = {
                'recv_mb_s': net_rates.get('recv_mb_s', 0),
                'sent_mb_s': net_rates.get('sent_mb_s', 0),
                'packets_dropped': net_io.dropin + net_io.dropout,
                'errors': net_io.errin + net_io.errout
            }
            
            if net_io.dropin + net_io.dropout > 100:
                bottlenecks.append({
                    'type': 'network_drops',
                    'severity': 'medium',
                    'value': net_io.dropin + net_io.dropout,
                    'message': f'Network packet drops detected: {net_io.dropin + net_io.dropout}',
                    'recommendation': 'Check network configuration and cable connections'
                })
            
            # Open file descriptors (Unix-like systems)
            if hasattr(psutil.Process(), 'num_fds'):
                try:
                    total_fds = sum(p.num_fds() for p in psutil.process_iter() 
                                  if hasattr(p, 'num_fds'))
                    # Get system limit
                    import resource
                    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
                    fd_percent = (total_fds / soft_limit) * 100
                    
                    metrics['file_descriptors'] = {
                        'used': total_fds,
                        'limit': soft_limit,
                        'percent': round(fd_percent, 2)
                    }
                    
                    if fd_percent > 80:
                        bottlenecks.append({
                            'type': 'file_descriptors',
                            'severity': 'high' if fd_percent > 90 else 'medium',
                            'value': fd_percent,
                            'message': f'High file descriptor usage: {fd_percent:.1f}%',
                            'recommendation': 'Some processes may have file descriptor leaks'
                        })
                except:
                    pass
            
            return {
                'timestamp': datetime.now().isoformat(),
                'bottlenecks': bottlenecks,
                'metrics': metrics,
                'summary': {
                    'total_bottlenecks': len(bottlenecks),
                    'high_severity': len([b for b in bottlenecks if b['severity'] == 'high']),
                    'medium_severity': len([b for b in bottlenecks if b['severity'] == 'medium'])
                }
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def historical_trend_analysis(self, metric_type: str = 'all', 
                                duration_minutes: int = 60) -> Dict[str, Any]:
        """
        Track metrics over time and identify trends
        
        Args:
            metric_type: Type of metric to analyze ('cpu', 'memory', 'disk', 'network', 'all')
            duration_minutes: How far back to analyze
            
        Returns:
            Dictionary containing trend analysis
        """
        # Take a snapshot first
        self._take_snapshot()
        
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        trends = {}
        
        with self._lock:
            for metric_name, history in self.metric_history.items():
                if metric_type != 'all' and not metric_name.startswith(metric_type):
                    continue
                
                # Filter by time
                recent_data = [(ts, val) for ts, val in history 
                             if ts > cutoff_time]
                
                if len(recent_data) < 2:
                    continue
                
                timestamps = [ts for ts, _ in recent_data]
                values = [val for _, val in recent_data]
                
                # Calculate trend
                trend_info = self._calculate_trend(timestamps, values)
                
                # Detect anomalies in recent data
                anomalies = self._detect_anomalies_in_series(values)
                
                trends[metric_name] = {
                    'current_value': values[-1] if values else None,
                    'average': statistics.mean(values) if values else None,
                    'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
                    'min': min(values) if values else None,
                    'max': max(values) if values else None,
                    'trend': trend_info['direction'],
                    'trend_strength': trend_info['strength'],
                    'change_percent': trend_info['change_percent'],
                    'anomalies': anomalies,
                    'data_points': len(values),
                    'time_range': {
                        'start': timestamps[0].isoformat() if timestamps else None,
                        'end': timestamps[-1].isoformat() if timestamps else None
                    }
                }
        
        # Generate predictions
        predictions = self._generate_predictions(trends)
        
        # Compare with baseline if available
        baseline_comparison = self._compare_with_baseline(trends)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'duration_minutes': duration_minutes,
            'trends': trends,
            'predictions': predictions,
            'baseline_comparison': baseline_comparison,
            'summary': self._summarize_trends(trends)
        }
    
    def anomaly_detection(self, real_time: bool = True) -> Dict[str, Any]:
        """
        Identify unusual system behavior
        
        Args:
            real_time: Perform real-time checks vs historical analysis only
            
        Returns:
            Dictionary containing detected anomalies
        """
        anomalies = []
        
        if real_time:
            # Real-time anomaly checks
            
            # Check for sudden CPU spikes
            cpu_samples = []
            for _ in range(5):
                cpu_samples.append(psutil.cpu_percent(interval=0.2))
            
            cpu_variance = statistics.variance(cpu_samples) if len(cpu_samples) > 1 else 0
            if cpu_variance > 400:  # High variance indicates instability
                anomalies.append({
                    'type': 'cpu_instability',
                    'severity': 'medium',
                    'details': {
                        'samples': cpu_samples,
                        'variance': cpu_variance
                    },
                    'message': 'CPU usage is highly unstable',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Check for unusual network connections
            unusual_connections = self._detect_unusual_connections()
            if unusual_connections:
                anomalies.extend(unusual_connections)
            
            # Check for suspicious processes
            suspicious_processes = self._detect_suspicious_processes()
            if suspicious_processes:
                anomalies.extend(suspicious_processes)
            
            # Port scan detection
            port_scan_activity = self._detect_port_scans()
            if port_scan_activity:
                anomalies.append(port_scan_activity)
        
        # Historical anomaly analysis
        with self._lock:
            for metric_name, history in self.metric_history.items():
                if len(history) < 10:
                    continue
                
                recent_values = [val for _, val in list(history)[-20:]]
                anomaly_indices = self._detect_anomalies_in_series(recent_values)
                
                for idx in anomaly_indices:
                    timestamp, value = list(history)[-20:][idx]
                    anomalies.append({
                        'type': 'metric_anomaly',
                        'severity': 'low',
                        'metric': metric_name,
                        'details': {
                            'value': value,
                            'expected_range': self._get_expected_range(recent_values),
                            'deviation': self._calculate_deviation(value, recent_values)
                        },
                        'message': f'Unusual value detected for {metric_name}',
                        'timestamp': timestamp.isoformat()
                    })
        
        # Behavioral anomalies
        behavioral_anomalies = self._detect_behavioral_anomalies()
        anomalies.extend(behavioral_anomalies)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'anomalies': anomalies,
            'summary': {
                'total_anomalies': len(anomalies),
                'by_severity': {
                    'high': len([a for a in anomalies if a.get('severity') == 'high']),
                    'medium': len([a for a in anomalies if a.get('severity') == 'medium']),
                    'low': len([a for a in anomalies if a.get('severity') == 'low'])
                },
                'by_type': self._count_by_type(anomalies)
            }
        }
    
    def set_baseline(self) -> Dict[str, Any]:
        """Capture current metrics as baseline for comparison"""
        self._take_snapshot()
        
        with self._lock:
            self.baseline_metrics = {}
            for metric_name, history in self.metric_history.items():
                if history:
                    values = [val for _, val in history]
                    self.baseline_metrics[metric_name] = {
                        'mean': statistics.mean(values),
                        'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
                        'min': min(values),
                        'max': max(values)
                    }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'baseline_set': True,
            'metrics_captured': len(self.baseline_metrics)
        }
    
    # Helper methods
    
    def _take_snapshot(self):
        """Take a snapshot of current system metrics"""
        timestamp = datetime.now()
        
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        self.metric_history['cpu.percent'].append((timestamp, cpu_percent))
        
        # Memory metrics
        memory = psutil.virtual_memory()
        self.metric_history['memory.percent'].append((timestamp, memory.percent))
        self.metric_history['memory.available_gb'].append(
            (timestamp, memory.available / 1024 / 1024 / 1024))
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        self.metric_history['disk.percent'].append((timestamp, disk.percent))
        
        # Network metrics
        net_io = psutil.net_io_counters()
        self.metric_history['network.bytes_sent'].append((timestamp, net_io.bytes_sent))
        self.metric_history['network.bytes_recv'].append((timestamp, net_io.bytes_recv))
        
        # Process count
        process_count = len(psutil.pids())
        self.metric_history['processes.count'].append((timestamp, process_count))
        
        self.last_snapshot_time = timestamp
    
    def _analyze_process_trees(self, processes: List[Dict]) -> List[Dict]:
        """Analyze process trees and their resource consumption"""
        # Build parent-child relationships
        children_by_parent = defaultdict(list)
        process_by_pid = {p['pid']: p for p in processes}
        
        for process in processes:
            if process.get('parent_pid'):
                children_by_parent[process['parent_pid']].append(process['pid'])
        
        # Find root processes and calculate tree totals
        trees = []
        processed_pids = set()
        
        for process in processes:
            if process['pid'] in processed_pids:
                continue
                
            # Find root of tree
            root_pid = process['pid']
            while root_pid in process_by_pid and process_by_pid[root_pid].get('parent_pid'):
                parent_pid = process_by_pid[root_pid]['parent_pid']
                if parent_pid not in process_by_pid:
                    break
                root_pid = parent_pid
            
            if root_pid not in processed_pids:
                # Calculate tree totals
                tree_pids = self._get_all_descendants(root_pid, children_by_parent)
                tree_pids.add(root_pid)
                
                total_cpu = sum(process_by_pid[pid]['cpu_percent'] 
                              for pid in tree_pids if pid in process_by_pid)
                total_memory = sum(process_by_pid[pid]['memory_percent'] 
                                 for pid in tree_pids if pid in process_by_pid)
                
                if root_pid in process_by_pid:
                    trees.append({
                        'root_pid': root_pid,
                        'root_name': process_by_pid[root_pid]['name'],
                        'total_processes': len(tree_pids),
                        'total_cpu_percent': round(total_cpu, 2),
                        'total_memory_percent': round(total_memory, 2),
                        'pids': list(tree_pids)
                    })
                
                processed_pids.update(tree_pids)
        
        return sorted(trees, key=lambda x: x['total_cpu_percent'], reverse=True)[:5]
    
    def _get_all_descendants(self, pid: int, children_by_parent: Dict) -> Set[int]:
        """Recursively get all descendant PIDs"""
        descendants = set()
        children = children_by_parent.get(pid, [])
        for child_pid in children:
            descendants.add(child_pid)
            descendants.update(self._get_all_descendants(child_pid, children_by_parent))
        return descendants
    
    def _calculate_io_rates(self, current_io) -> Dict[str, float]:
        """Calculate I/O rates from current and previous snapshots"""
        rates = {}
        
        # Check if we have previous data
        if hasattr(self, '_last_disk_io') and self._last_disk_io_time:
            time_delta = time.time() - self._last_disk_io_time
            if time_delta > 0:
                rates['read_mb_s'] = ((current_io.read_bytes - self._last_disk_io.read_bytes) 
                                    / 1024 / 1024 / time_delta)
                rates['write_mb_s'] = ((current_io.write_bytes - self._last_disk_io.write_bytes) 
                                     / 1024 / 1024 / time_delta)
                
                # Estimate busy time (simplified)
                total_io = (current_io.read_count + current_io.write_count - 
                          self._last_disk_io.read_count - self._last_disk_io.write_count)
                rates['busy_percent'] = min(100, (total_io / time_delta) / 10)
        
        self._last_disk_io = current_io
        self._last_disk_io_time = time.time()
        
        return rates
    
    def _calculate_network_rates(self, current_net) -> Dict[str, float]:
        """Calculate network rates from current and previous snapshots"""
        rates = {}
        
        if hasattr(self, '_last_net_io') and self._last_net_io_time:
            time_delta = time.time() - self._last_net_io_time
            if time_delta > 0:
                rates['recv_mb_s'] = ((current_net.bytes_recv - self._last_net_io.bytes_recv) 
                                    / 1024 / 1024 / time_delta)
                rates['sent_mb_s'] = ((current_net.bytes_sent - self._last_net_io.bytes_sent) 
                                    / 1024 / 1024 / time_delta)
        
        self._last_net_io = current_net
        self._last_net_io_time = time.time()
        
        return rates
    
    def _calculate_trend(self, timestamps: List[datetime], values: List[float]) -> Dict:
        """Calculate trend direction and strength"""
        if len(values) < 2:
            return {'direction': 'stable', 'strength': 0, 'change_percent': 0}
        
        # Simple linear regression
        n = len(values)
        x = list(range(n))
        
        x_mean = sum(x) / n
        y_mean = sum(values) / n
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator
        
        # Calculate change percentage
        if values[0] != 0:
            change_percent = ((values[-1] - values[0]) / values[0]) * 100
        else:
            change_percent = 0
        
        # Determine trend
        if abs(slope) < 0.1:
            direction = 'stable'
        elif slope > 0:
            direction = 'increasing'
        else:
            direction = 'decreasing'
        
        strength = min(100, abs(slope) * 10)  # Normalize to 0-100
        
        return {
            'direction': direction,
            'strength': round(strength, 2),
            'change_percent': round(change_percent, 2)
        }
    
    def _detect_anomalies_in_series(self, values: List[float]) -> List[int]:
        """Detect anomalies using statistical methods"""
        if len(values) < 3:
            return []
        
        anomalies = []
        mean = statistics.mean(values)
        std_dev = statistics.stdev(values)
        
        for i, value in enumerate(values):
            z_score = abs((value - mean) / std_dev) if std_dev > 0 else 0
            if z_score > self.anomaly_threshold:
                anomalies.append(i)
        
        return anomalies
    
    def _detect_unusual_connections(self) -> List[Dict]:
        """Detect unusual network connections"""
        anomalies = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            # Group by remote address
            remote_addrs = defaultdict(int)
            for conn in connections:
                if conn.raddr and conn.status == 'ESTABLISHED':
                    remote_addrs[conn.raddr.ip] += 1
            
            # Check for suspicious patterns
            for addr, count in remote_addrs.items():
                # Many connections to single IP
                if count > 20:
                    anomalies.append({
                        'type': 'excessive_connections',
                        'severity': 'medium',
                        'details': {
                            'remote_address': addr,
                            'connection_count': count
                        },
                        'message': f'Excessive connections to {addr}: {count}',
                        'timestamp': datetime.now().isoformat()
                    })
                
                # Check for unusual ports
                unusual_ports = [conn.raddr.port for conn in connections 
                               if conn.raddr and conn.raddr.ip == addr 
                               and conn.raddr.port not in [80, 443, 22, 3389]]
                
                if len(unusual_ports) > 5:
                    anomalies.append({
                        'type': 'unusual_ports',
                        'severity': 'low',
                        'details': {
                            'remote_address': addr,
                            'ports': unusual_ports[:10]
                        },
                        'message': f'Connections to unusual ports on {addr}',
                        'timestamp': datetime.now().isoformat()
                    })
        
        except (psutil.AccessDenied, Exception):
            pass
        
        return anomalies
    
    def _detect_suspicious_processes(self) -> List[Dict]:
        """Detect potentially suspicious processes"""
        anomalies = []
        suspicious_names = ['nc', 'ncat', 'netcat', 'cryptominer', 'xmrig']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    info = proc.info
                    name_lower = info['name'].lower()
                    
                    # Check for suspicious process names
                    for suspicious in suspicious_names:
                        if suspicious in name_lower:
                            anomalies.append({
                                'type': 'suspicious_process',
                                'severity': 'high',
                                'details': {
                                    'pid': info['pid'],
                                    'name': info['name'],
                                    'exe': info.get('exe', 'unknown')
                                },
                                'message': f'Suspicious process detected: {info["name"]}',
                                'timestamp': datetime.now().isoformat()
                            })
                    
                    # Check for hidden processes (no exe path)
                    if info.get('exe') is None and name_lower not in ['kernel_task', 'system']:
                        anomalies.append({
                            'type': 'hidden_process',
                            'severity': 'medium',
                            'details': {
                                'pid': info['pid'],
                                'name': info['name']
                            },
                            'message': f'Process with no executable path: {info["name"]}',
                            'timestamp': datetime.now().isoformat()
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception:
            pass
        
        return anomalies
    
    def _detect_port_scans(self) -> Optional[Dict]:
        """Detect potential port scanning activity"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            # Count SYN_SENT connections by source
            syn_sent_count = defaultdict(int)
            for conn in connections:
                if conn.status == 'SYN_SENT' and conn.laddr:
                    syn_sent_count[conn.laddr.ip] += 1
            
            # High number of SYN_SENT might indicate scanning
            for addr, count in syn_sent_count.items():
                if count > 10:
                    return {
                        'type': 'port_scan',
                        'severity': 'high',
                        'details': {
                            'source_address': addr,
                            'syn_sent_count': count
                        },
                        'message': f'Possible port scan detected from {addr}',
                        'timestamp': datetime.now().isoformat()
                    }
        
        except (psutil.AccessDenied, Exception):
            pass
        
        return None
    
    def _detect_behavioral_anomalies(self) -> List[Dict]:
        """Detect anomalies based on system behavior patterns"""
        anomalies = []
        
        # Check for rapid process creation
        current_process_count = len(psutil.pids())
        
        if hasattr(self, '_last_process_count') and hasattr(self, '_last_process_check'):
            time_delta = time.time() - self._last_process_check
            if time_delta > 0:
                process_rate = (current_process_count - self._last_process_count) / time_delta
                if process_rate > 10:  # More than 10 new processes per second
                    anomalies.append({
                        'type': 'rapid_process_creation',
                        'severity': 'medium',
                        'details': {
                            'rate_per_second': round(process_rate, 2),
                            'new_processes': current_process_count - self._last_process_count
                        },
                        'message': 'Unusually rapid process creation detected',
                        'timestamp': datetime.now().isoformat()
                    })
        
        self._last_process_count = current_process_count
        self._last_process_check = time.time()
        
        return anomalies
    
    def _generate_predictions(self, trends: Dict) -> Dict[str, Any]:
        """Generate predictions based on trends"""
        predictions = {}
        
        for metric, trend_data in trends.items():
            if trend_data['data_points'] < 5:
                continue
            
            # Simple prediction based on trend
            if trend_data['trend'] == 'increasing':
                if 'cpu' in metric and trend_data['current_value'] > 70:
                    predictions[metric] = {
                        'prediction': 'likely_bottleneck',
                        'timeframe': '30 minutes',
                        'confidence': min(90, trend_data['trend_strength'])
                    }
                elif 'memory' in metric and trend_data['current_value'] > 80:
                    predictions[metric] = {
                        'prediction': 'memory_exhaustion',
                        'timeframe': '1 hour',
                        'confidence': min(85, trend_data['trend_strength'])
                    }
            elif trend_data['trend'] == 'decreasing':
                if trend_data['current_value'] < 20:
                    predictions[metric] = {
                        'prediction': 'stabilizing',
                        'timeframe': '15 minutes',
                        'confidence': 70
                    }
        
        return predictions
    
    def _compare_with_baseline(self, trends: Dict) -> Dict[str, Any]:
        """Compare current trends with baseline"""
        if not self.baseline_metrics:
            return {'baseline_set': False}
        
        comparisons = {}
        
        for metric, trend_data in trends.items():
            if metric in self.baseline_metrics:
                baseline = self.baseline_metrics[metric]
                current = trend_data['current_value']
                
                if baseline['mean'] > 0:
                    deviation_percent = ((current - baseline['mean']) / baseline['mean']) * 100
                else:
                    deviation_percent = 0
                
                comparisons[metric] = {
                    'baseline_mean': baseline['mean'],
                    'current_value': current,
                    'deviation_percent': round(deviation_percent, 2),
                    'within_normal_range': (baseline['min'] <= current <= baseline['max'])
                }
        
        return {
            'baseline_set': True,
            'comparisons': comparisons
        }
    
    def _summarize_trends(self, trends: Dict) -> Dict[str, Any]:
        """Generate summary of trends"""
        summary = {
            'increasing': [],
            'decreasing': [],
            'stable': [],
            'with_anomalies': []
        }
        
        for metric, trend_data in trends.items():
            if trend_data['anomalies']:
                summary['with_anomalies'].append(metric)
            
            if trend_data['trend'] == 'increasing' and trend_data['trend_strength'] > 20:
                summary['increasing'].append({
                    'metric': metric,
                    'strength': trend_data['trend_strength'],
                    'change': trend_data['change_percent']
                })
            elif trend_data['trend'] == 'decreasing' and trend_data['trend_strength'] > 20:
                summary['decreasing'].append({
                    'metric': metric,
                    'strength': trend_data['trend_strength'],
                    'change': trend_data['change_percent']
                })
            else:
                summary['stable'].append(metric)
        
        return summary
    
    def _get_expected_range(self, values: List[float]) -> Tuple[float, float]:
        """Get expected range based on recent values"""
        if not values:
            return (0, 0)
        
        mean = statistics.mean(values)
        std_dev = statistics.stdev(values) if len(values) > 1 else 0
        
        return (
            mean - (self.anomaly_threshold * std_dev),
            mean + (self.anomaly_threshold * std_dev)
        )
    
    def _calculate_deviation(self, value: float, values: List[float]) -> float:
        """Calculate how many standard deviations a value is from the mean"""
        if not values:
            return 0
        
        mean = statistics.mean(values)
        std_dev = statistics.stdev(values) if len(values) > 1 else 0
        
        if std_dev == 0:
            return 0
        
        return abs((value - mean) / std_dev)
    
    def _count_by_type(self, anomalies: List[Dict]) -> Dict[str, int]:
        """Count anomalies by type"""
        counts = defaultdict(int)
        for anomaly in anomalies:
            counts[anomaly['type']] += 1
        return dict(counts)


# Convenience functions for Claude Code

def process_analysis(top_n: int = 10, include_children: bool = True) -> Dict[str, Any]:
    """Analyze system processes and identify resource-intensive ones"""
    diag = AdvancedDiagnostics()
    return diag.process_analysis(top_n, include_children)


def system_bottleneck_detection() -> Dict[str, Any]:
    """Detect system performance bottlenecks"""
    diag = AdvancedDiagnostics()
    return diag.system_bottleneck_detection()


def historical_trend_analysis(metric_type: str = 'all', 
                            duration_minutes: int = 60) -> Dict[str, Any]:
    """Analyze historical trends in system metrics"""
    diag = AdvancedDiagnostics()
    # Take multiple snapshots to build history
    for _ in range(5):
        diag._take_snapshot()
        time.sleep(1)
    return diag.historical_trend_analysis(metric_type, duration_minutes)


def anomaly_detection(real_time: bool = True) -> Dict[str, Any]:
    """Detect anomalies in system behavior"""
    diag = AdvancedDiagnostics()
    return diag.anomaly_detection(real_time)


# Quick diagnostic function for common scenarios
def diagnose_slow_system() -> Dict[str, Any]:
    """Comprehensive diagnosis for slow system performance"""
    results = {
        'timestamp': datetime.now().isoformat(),
        'diagnosis': {}
    }
    
    # Check bottlenecks
    bottlenecks = system_bottleneck_detection()
    results['bottlenecks'] = bottlenecks
    
    # Analyze processes
    processes = process_analysis(top_n=5)
    results['top_processes'] = {
        'cpu': processes['top_cpu_consumers'],
        'memory': processes['top_memory_consumers']
    }
    
    # Detect anomalies
    anomalies = anomaly_detection()
    results['anomalies'] = anomalies
    
    # Generate recommendations
    recommendations = []
    
    if bottlenecks['bottlenecks']:
        for bottleneck in bottlenecks['bottlenecks']:
            recommendations.append(bottleneck['recommendation'])
    
    if processes['top_cpu_consumers'] and processes['top_cpu_consumers'][0]['cpu_percent'] > 50:
        top_proc = processes['top_cpu_consumers'][0]
        recommendations.append(
            f"Process '{top_proc['name']}' (PID: {top_proc['pid']}) "
            f"is using {top_proc['cpu_percent']:.1f}% CPU"
        )
    
    results['recommendations'] = recommendations
    
    return results