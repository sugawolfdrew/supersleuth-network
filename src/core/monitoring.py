"""
Continuous monitoring module for SuperSleuth Network
Provides real-time network monitoring and alerting capabilities
"""

import time
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

from ..diagnostics.performance_analysis import PerformanceAnalysis
from ..diagnostics.network_discovery import NetworkDiscovery
from ..utils.logger import get_logger


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Network alert data structure"""
    timestamp: datetime
    severity: AlertSeverity
    category: str
    title: str
    description: str
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'metric_value': self.metric_value,
            'threshold': self.threshold
        }


class MetricCollector:
    """Collects and stores network metrics"""
    
    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self.metrics_history = {
            'bandwidth': [],
            'latency': [],
            'packet_loss': [],
            'device_count': [],
            'cpu_usage': [],
            'memory_usage': []
        }
        self.logger = get_logger(self.__class__.__name__)
    
    def add_metric(self, metric_type: str, value: float, timestamp: Optional[datetime] = None):
        """Add a metric value"""
        
        if metric_type not in self.metrics_history:
            self.metrics_history[metric_type] = []
        
        if timestamp is None:
            timestamp = datetime.now()
        
        self.metrics_history[metric_type].append({
            'timestamp': timestamp,
            'value': value
        })
        
        # Clean old data
        self._cleanup_old_metrics(metric_type)
    
    def _cleanup_old_metrics(self, metric_type: str):
        """Remove metrics older than retention period"""
        
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
        
        self.metrics_history[metric_type] = [
            m for m in self.metrics_history[metric_type]
            if m['timestamp'] > cutoff_time
        ]
    
    def get_metric_stats(self, metric_type: str, minutes: int = 60) -> Dict[str, float]:
        """Get statistics for a metric over specified time period"""
        
        if metric_type not in self.metrics_history:
            return {}
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent_metrics = [
            m['value'] for m in self.metrics_history[metric_type]
            if m['timestamp'] > cutoff_time
        ]
        
        if not recent_metrics:
            return {}
        
        return {
            'current': recent_metrics[-1],
            'average': sum(recent_metrics) / len(recent_metrics),
            'min': min(recent_metrics),
            'max': max(recent_metrics),
            'samples': len(recent_metrics)
        }
    
    def save_to_file(self, filepath: Path):
        """Save metrics history to file"""
        
        data_to_save = {}
        for metric_type, values in self.metrics_history.items():
            data_to_save[metric_type] = [
                {
                    'timestamp': m['timestamp'].isoformat(),
                    'value': m['value']
                }
                for m in values
            ]
        
        with open(filepath, 'w') as f:
            json.dump(data_to_save, f, indent=2)
    
    def load_from_file(self, filepath: Path):
        """Load metrics history from file"""
        
        if not filepath.exists():
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            for metric_type, values in data.items():
                self.metrics_history[metric_type] = [
                    {
                        'timestamp': datetime.fromisoformat(m['timestamp']),
                        'value': m['value']
                    }
                    for m in values
                ]
            
            # Clean old data
            for metric_type in self.metrics_history:
                self._cleanup_old_metrics(metric_type)
                
        except Exception as e:
            self.logger.error(f"Failed to load metrics history: {str(e)}")


class NetworkMonitor:
    """Continuous network monitoring system"""
    
    def __init__(self, client_config: Dict[str, Any], check_interval: int = 60):
        """
        Initialize network monitor
        
        Args:
            client_config: Client configuration
            check_interval: Seconds between monitoring checks
        """
        self.client_config = client_config
        self.check_interval = check_interval
        self.logger = get_logger(self.__class__.__name__)
        
        # Components
        self.metric_collector = MetricCollector()
        self.alert_queue = queue.Queue()
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        
        # Thresholds
        self.thresholds = {
            'bandwidth_min_mbps': 50,
            'latency_max_ms': 100,
            'packet_loss_max_percent': 1.0,
            'device_count_change_percent': 20,
            'cpu_max_percent': 80,
            'memory_max_percent': 85
        }
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        self.last_known_devices = set()
        
    def start(self):
        """Start continuous monitoring"""
        
        if self.monitoring_active:
            self.logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("Network monitoring started")
    
    def stop(self):
        """Stop continuous monitoring"""
        
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Network monitoring stopped")
    
    def set_threshold(self, metric: str, value: float):
        """Update monitoring threshold"""
        
        if metric in self.thresholds:
            old_value = self.thresholds[metric]
            self.thresholds[metric] = value
            self.logger.info(f"Updated threshold {metric}: {old_value} -> {value}")
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add callback function for alerts"""
        
        self.alert_callbacks.append(callback)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        
        while self.monitoring_active:
            try:
                # Collect metrics
                self._collect_performance_metrics()
                self._collect_system_metrics()
                self._check_device_changes()
                
                # Check thresholds and generate alerts
                self._check_thresholds()
                
                # Process alert queue
                self._process_alerts()
                
                # Wait for next check
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}")
                time.sleep(self.check_interval)
    
    def _collect_performance_metrics(self):
        """Collect network performance metrics"""
        
        try:
            # Quick performance check
            perf_config = {
                'test_duration': 10,  # Quick test
                'test_interval': 2
            }
            
            # In production, would use actual performance analysis
            # For demo, simulate metrics
            import random
            
            # Simulate bandwidth
            bandwidth = 80 + random.randint(-20, 20)
            self.metric_collector.add_metric('bandwidth', bandwidth)
            
            # Simulate latency
            latency = 30 + random.randint(-10, 20)
            self.metric_collector.add_metric('latency', latency)
            
            # Simulate packet loss
            packet_loss = random.uniform(0, 0.5)
            self.metric_collector.add_metric('packet_loss', packet_loss)
            
        except Exception as e:
            self.logger.error(f"Failed to collect performance metrics: {str(e)}")
    
    def _collect_system_metrics(self):
        """Collect system resource metrics"""
        
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.metric_collector.add_metric('cpu_usage', cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.metric_collector.add_metric('memory_usage', memory.percent)
            
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {str(e)}")
    
    def _check_device_changes(self):
        """Monitor for device changes on network"""
        
        try:
            # In production, would use NetworkDiscovery
            # For demo, simulate device count
            import random
            
            device_count = 25 + random.randint(-5, 5)
            self.metric_collector.add_metric('device_count', device_count)
            
            # Check for significant changes
            stats = self.metric_collector.get_metric_stats('device_count', minutes=10)
            
            if stats and 'average' in stats:
                change_percent = abs(stats['current'] - stats['average']) / stats['average'] * 100
                
                if change_percent > self.thresholds['device_count_change_percent']:
                    self._create_alert(
                        AlertSeverity.WARNING,
                        'device_change',
                        'Significant Device Count Change',
                        f'Device count changed by {change_percent:.1f}% in last 10 minutes',
                        metric_value=stats['current'],
                        threshold=self.thresholds['device_count_change_percent']
                    )
            
        except Exception as e:
            self.logger.error(f"Failed to check device changes: {str(e)}")
    
    def _check_thresholds(self):
        """Check metrics against thresholds and generate alerts"""
        
        # Check bandwidth
        bandwidth_stats = self.metric_collector.get_metric_stats('bandwidth', minutes=5)
        if bandwidth_stats and bandwidth_stats['current'] < self.thresholds['bandwidth_min_mbps']:
            self._create_alert(
                AlertSeverity.WARNING,
                'performance',
                'Low Bandwidth Detected',
                f"Bandwidth dropped to {bandwidth_stats['current']:.1f} Mbps",
                metric_value=bandwidth_stats['current'],
                threshold=self.thresholds['bandwidth_min_mbps']
            )
        
        # Check latency
        latency_stats = self.metric_collector.get_metric_stats('latency', minutes=5)
        if latency_stats and latency_stats['average'] > self.thresholds['latency_max_ms']:
            self._create_alert(
                AlertSeverity.WARNING,
                'performance',
                'High Latency Detected',
                f"Average latency is {latency_stats['average']:.1f} ms",
                metric_value=latency_stats['average'],
                threshold=self.thresholds['latency_max_ms']
            )
        
        # Check packet loss
        loss_stats = self.metric_collector.get_metric_stats('packet_loss', minutes=5)
        if loss_stats and loss_stats['average'] > self.thresholds['packet_loss_max_percent']:
            self._create_alert(
                AlertSeverity.CRITICAL,
                'performance',
                'Packet Loss Detected',
                f"Packet loss averaging {loss_stats['average']:.2f}%",
                metric_value=loss_stats['average'],
                threshold=self.thresholds['packet_loss_max_percent']
            )
        
        # Check system resources
        cpu_stats = self.metric_collector.get_metric_stats('cpu_usage', minutes=5)
        if cpu_stats and cpu_stats['average'] > self.thresholds['cpu_max_percent']:
            self._create_alert(
                AlertSeverity.WARNING,
                'system',
                'High CPU Usage',
                f"CPU usage averaging {cpu_stats['average']:.1f}%",
                metric_value=cpu_stats['average'],
                threshold=self.thresholds['cpu_max_percent']
            )
    
    def _create_alert(self, severity: AlertSeverity, category: str, title: str, 
                     description: str, metric_value: Optional[float] = None,
                     threshold: Optional[float] = None):
        """Create and queue an alert"""
        
        alert = Alert(
            timestamp=datetime.now(),
            severity=severity,
            category=category,
            title=title,
            description=description,
            metric_value=metric_value,
            threshold=threshold
        )
        
        self.alert_queue.put(alert)
        self.logger.info(f"Alert created: {title} ({severity.value})")
    
    def _process_alerts(self):
        """Process queued alerts"""
        
        while not self.alert_queue.empty():
            try:
                alert = self.alert_queue.get_nowait()
                
                # Call registered callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self.logger.error(f"Alert callback error: {str(e)}")
                
            except queue.Empty:
                break
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metric values"""
        
        metrics = {}
        
        for metric_type in self.metric_collector.metrics_history:
            stats = self.metric_collector.get_metric_stats(metric_type, minutes=5)
            if stats:
                metrics[metric_type] = stats
        
        return metrics
    
    def get_metric_history(self, metric_type: str, hours: int = 1) -> List[Dict[str, Any]]:
        """Get metric history"""
        
        if metric_type not in self.metric_collector.metrics_history:
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        return [
            {
                'timestamp': m['timestamp'].isoformat(),
                'value': m['value']
            }
            for m in self.metric_collector.metrics_history[metric_type]
            if m['timestamp'] > cutoff_time
        ]