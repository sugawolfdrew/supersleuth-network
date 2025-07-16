"""
SuperSleuth Network Web Dashboard
Lightweight local web interface for viewing diagnostic results
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime
from pathlib import Path
import threading
import time
from typing import Dict, List, Any, Optional

# Add parent directory to path for imports
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.supersleuth import SuperSleuthNetwork
from src.utils.logger import get_logger
from src.core.event_logger import event_logger, EventType, EventSeverity


class DashboardServer:
    """Web dashboard server for SuperSleuth Network"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 5000):
        self.host = host
        self.port = port
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        CORS(self.app)  # Enable CORS for API access
        
        self.logger = get_logger("WebDashboard")
        
        # Data storage
        self.current_session: Optional[SuperSleuthNetwork] = None
        self.diagnostic_history = []
        self.real_time_metrics = {
            'network_health': 0,
            'active_devices': 0,
            'bandwidth_usage': 0,
            'security_score': 0,
            'last_update': None
        }
        
        # Background monitoring thread
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Event stream
        self.event_buffer = []
        self.max_events = 100
        
        # Subscribe to events
        event_logger.subscribe(self._handle_event)
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/status')
        def get_status():
            """Get current system status"""
            return jsonify({
                'status': 'active' if self.current_session else 'idle',
                'session_id': self.current_session.session_id if self.current_session else None,
                'monitoring': self.monitoring_active,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/api/metrics')
        def get_metrics():
            """Get real-time metrics"""
            return jsonify(self.real_time_metrics)
        
        @self.app.route('/api/diagnostics/history')
        def get_diagnostic_history():
            """Get diagnostic history"""
            return jsonify(self.diagnostic_history[-10:])  # Last 10 diagnostics
        
        @self.app.route('/api/diagnostics/current')
        def get_current_diagnostics():
            """Get current diagnostic results"""
            if not self.current_session:
                return jsonify({'error': 'No active session'}), 404
            
            findings = {}
            for diag_type, result in self.current_session.findings.items():
                # Simplify results for dashboard display
                findings[diag_type] = self._simplify_diagnostic_result(result)
            
            return jsonify({
                'session_id': self.current_session.session_id,
                'findings': findings,
                'recommendations': self.current_session.get_recommendations()[:5],
                'health_score': self.current_session._calculate_overall_health_score()
            })
        
        @self.app.route('/api/events/recent')
        def get_recent_events():
            """Get recent events"""
            limit = request.args.get('limit', 50, type=int)
            event_type = request.args.get('type')
            severity = request.args.get('severity')
            
            # Get events from logger
            events = event_logger.get_recent_events(
                limit=limit,
                event_type=EventType(event_type) if event_type else None,
                severity=EventSeverity(severity) if severity else None
            )
            
            return jsonify(events)
        
        @self.app.route('/api/events/stream')
        def event_stream():
            """Server-sent events stream"""
            def generate():
                # Send recent events first
                for event in self.event_buffer[-20:]:
                    yield f"data: {json.dumps(event)}\n\n"
                
                # Then stream new events
                last_index = len(self.event_buffer)
                while True:
                    if len(self.event_buffer) > last_index:
                        # Send new events
                        for event in self.event_buffer[last_index:]:
                            yield f"data: {json.dumps(event)}\n\n"
                        last_index = len(self.event_buffer)
                    time.sleep(0.5)
            
            from flask import Response
            return Response(generate(), mimetype='text/event-stream')
        
        @self.app.route('/api/diagnostics/run', methods=['POST'])
        def run_diagnostic():
            """Run a specific diagnostic"""
            data = request.json
            diagnostic_type = data.get('type')
            
            if not self.current_session:
                # Create new session
                client_config = {
                    'client_name': data.get('client_name', 'Local Network'),
                    'sow_reference': 'DEMO-001',
                    'authorized_subnets': ['192.168.1.0/24'],
                    'compliance_requirements': ['SOC2'],
                    'escalation_contacts': ['admin@local']
                }
                
                technician_profile = {
                    'name': data.get('technician_name', 'Admin'),
                    'skill_level': 'intermediate'
                }
                
                self.current_session = SuperSleuthNetwork(client_config, technician_profile)
                self.current_session.start_diagnostic_session(
                    data.get('issue', 'General network assessment')
                )
            
            # Run diagnostic (simplified for demo)
            result = {
                'status': 'completed',
                'message': f'{diagnostic_type} diagnostic completed',
                'timestamp': datetime.now().isoformat()
            }
            
            # Add to history
            self.diagnostic_history.append({
                'type': diagnostic_type,
                'timestamp': datetime.now().isoformat(),
                'status': 'completed'
            })
            
            return jsonify(result)
        
        @self.app.route('/api/monitoring/start', methods=['POST'])
        def start_monitoring():
            """Start continuous monitoring"""
            if not self.monitoring_active:
                self.monitoring_active = True
                self.monitor_thread = threading.Thread(target=self._monitoring_loop)
                self.monitor_thread.daemon = True
                self.monitor_thread.start()
                return jsonify({'status': 'monitoring started'})
            return jsonify({'status': 'already monitoring'})
        
        @self.app.route('/api/monitoring/stop', methods=['POST'])
        def stop_monitoring():
            """Stop continuous monitoring"""
            self.monitoring_active = False
            return jsonify({'status': 'monitoring stopped'})
        
        @self.app.route('/api/reports/generate', methods=['POST'])
        def generate_report():
            """Generate report for specific audience"""
            data = request.json
            audience = data.get('audience', 'it_professional')
            
            if not self.current_session:
                return jsonify({'error': 'No active session'}), 404
            
            try:
                report = self.current_session.generate_report(audience)
                report_path = self.current_session.save_report(report, audience)
                
                return jsonify({
                    'status': 'success',
                    'path': str(report_path),
                    'preview': report[:500] + '...'
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _simplify_diagnostic_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Simplify diagnostic result for dashboard display"""
        
        simplified = {
            'status': result.get('status', 'unknown'),
            'timestamp': result.get('timestamp', datetime.now().isoformat())
        }
        
        # Extract key metrics based on result content
        if 'results' in result:
            results = result['results']
            
            # Network discovery metrics
            if 'total_devices' in results:
                simplified['total_devices'] = results['total_devices']
                simplified['device_types'] = results.get('network_map', {}).get('device_types', {})
            
            # Performance metrics
            if 'performance_metrics' in results:
                metrics = results['performance_metrics']
                if 'bandwidth' in metrics:
                    simplified['bandwidth'] = metrics['bandwidth']
                if 'latency' in metrics:
                    simplified['latency'] = metrics['latency']
            
            # Security metrics
            if 'overall_risk_score' in results:
                simplified['risk_score'] = results['overall_risk_score']
                simplified['security_score'] = 100 - results['overall_risk_score']
            
            # WiFi metrics
            if 'signal_analysis' in results:
                simplified['coverage_issues'] = len(
                    results['signal_analysis'].get('coverage_issues', [])
                )
        
        return simplified
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        
        while self.monitoring_active:
            try:
                # Update real-time metrics (simulated for demo)
                self.real_time_metrics.update({
                    'network_health': min(100, self.real_time_metrics['network_health'] + 
                                         (5 if self.real_time_metrics['network_health'] < 80 else -2)),
                    'active_devices': 25 + int(time.time() % 10),
                    'bandwidth_usage': 30 + int(time.time() % 40),
                    'security_score': 85 + int(time.time() % 10),
                    'last_update': datetime.now().isoformat()
                })
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}")
                time.sleep(5)
    
    def run(self):
        """Run the dashboard server"""
        
        print(f"""
🌐 SUPERSLEUTH NETWORK DASHBOARD
================================

Dashboard starting at: http://{self.host}:{self.port}

Open your web browser to view the dashboard.
Press Ctrl+C to stop the server.
        """)
        
        self.app.run(host=self.host, port=self.port, debug=False)
    
    def _handle_event(self, event):
        """Handle incoming events for the dashboard"""
        event_dict = event.to_dict()
        self.event_buffer.append(event_dict)
        
        # Limit buffer size
        if len(self.event_buffer) > self.max_events:
            self.event_buffer.pop(0)


def create_dashboard_templates():
    """Create HTML templates for the dashboard"""
    
    # Create template directory
    template_dir = Path(__file__).parent / 'templates'
    template_dir.mkdir(exist_ok=True)
    
    # Create static directory
    static_dir = Path(__file__).parent / 'static'
    static_dir.mkdir(exist_ok=True)
    
    # Create dashboard HTML
    dashboard_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SuperSleuth Network Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='dashboard.css') }}">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard">
        <header>
            <h1>🔍 SuperSleuth Network Dashboard</h1>
            <div class="status-bar">
                <span id="connection-status" class="status-indicator">●</span>
                <span id="session-info">No Active Session</span>
                <span id="current-time"></span>
            </div>
        </header>
        
        <main>
            <!-- Metrics Overview -->
            <section class="metrics-grid">
                <div class="metric-card">
                    <h3>Network Health</h3>
                    <div class="metric-value">
                        <span id="health-score">--</span>%
                    </div>
                    <div class="metric-chart">
                        <canvas id="health-chart"></canvas>
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>Active Devices</h3>
                    <div class="metric-value">
                        <span id="device-count">--</span>
                    </div>
                    <div class="device-types" id="device-breakdown"></div>
                </div>
                
                <div class="metric-card">
                    <h3>Bandwidth Usage</h3>
                    <div class="metric-value">
                        <span id="bandwidth-usage">--</span>%
                    </div>
                    <div class="bandwidth-details">
                        <small>Download: <span id="download-speed">--</span> Mbps</small>
                        <small>Upload: <span id="upload-speed">--</span> Mbps</small>
                    </div>
                </div>
                
                <div class="metric-card">
                    <h3>Security Score</h3>
                    <div class="metric-value">
                        <span id="security-score">--</span>%
                    </div>
                    <div class="security-status" id="security-status">
                        <small>Status: <span id="security-level">--</span></small>
                    </div>
                </div>
            </section>
            
            <!-- Control Panel -->
            <section class="control-panel">
                <h2>Diagnostic Controls</h2>
                <div class="controls">
                    <button onclick="runDiagnostic('network_discovery')" class="btn btn-primary">
                        🔍 Network Discovery
                    </button>
                    <button onclick="runDiagnostic('performance_analysis')" class="btn btn-primary">
                        📊 Performance Test
                    </button>
                    <button onclick="runDiagnostic('wifi_analysis')" class="btn btn-primary">
                        📡 WiFi Analysis
                    </button>
                    <button onclick="runDiagnostic('security_assessment')" class="btn btn-primary">
                        🔒 Security Scan
                    </button>
                </div>
                
                <div class="monitoring-controls">
                    <button id="monitor-toggle" onclick="toggleMonitoring()" class="btn btn-secondary">
                        ▶️ Start Monitoring
                    </button>
                    <button onclick="generateReport('it_professional')" class="btn btn-secondary">
                        📄 Generate IT Report
                    </button>
                    <button onclick="generateReport('business')" class="btn btn-secondary">
                        📄 Generate Business Report
                    </button>
                </div>
            </section>
            
            <!-- Results Panel -->
            <section class="results-panel">
                <div class="recommendations">
                    <h2>📋 Current Recommendations</h2>
                    <ul id="recommendations-list">
                        <li>No recommendations yet - run diagnostics first</li>
                    </ul>
                </div>
                
                <div class="diagnostic-history">
                    <h2>📊 Recent Diagnostics</h2>
                    <div id="history-list">
                        <p>No diagnostics run yet</p>
                    </div>
                </div>
            </section>
            
            <!-- Alerts Panel -->
            <section class="alerts-panel">
                <h2>🚨 Active Alerts</h2>
                <div id="alerts-list">
                    <p class="no-alerts">No active alerts</p>
                </div>
            </section>
        </main>
    </div>
    
    <script src="{{ url_for('static', filename='dashboard.js') }}"></script>
</body>
</html>'''
    
    # Create CSS
    dashboard_css = '''/* SuperSleuth Network Dashboard Styles */

:root {
    --primary-color: #2563eb;
    --secondary-color: #64748b;
    --success-color: #22c55e;
    --warning-color: #f59e0b;
    --danger-color: #ef4444;
    --background: #0f172a;
    --surface: #1e293b;
    --surface-light: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--background);
    color: var(--text-primary);
    line-height: 1.6;
}

.dashboard {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header */
header {
    background-color: var(--surface);
    padding: 1rem 2rem;
    border-bottom: 1px solid var(--surface-light);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

h1 {
    font-size: 1.5rem;
    font-weight: 600;
}

.status-bar {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    color: var(--text-secondary);
}

.status-indicator {
    font-size: 0.8rem;
    color: var(--success-color);
}

.status-indicator.offline {
    color: var(--danger-color);
}

/* Main Content */
main {
    flex: 1;
    padding: 2rem;
    display: grid;
    gap: 2rem;
}

/* Metrics Grid */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
}

.metric-card {
    background-color: var(--surface);
    border-radius: 0.5rem;
    padding: 1.5rem;
    border: 1px solid var(--surface-light);
}

.metric-card h3 {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.metric-value {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.metric-chart {
    height: 60px;
    margin-top: 1rem;
}

.device-types,
.bandwidth-details,
.security-status {
    font-size: 0.875rem;
    color: var(--text-secondary);
}

/* Control Panel */
.control-panel {
    background-color: var(--surface);
    border-radius: 0.5rem;
    padding: 1.5rem;
    border: 1px solid var(--surface-light);
}

.control-panel h2 {
    font-size: 1.25rem;
    margin-bottom: 1rem;
}

.controls,
.monitoring-controls {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
}

.btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    border: none;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.btn-primary {
    background-color: var(--primary-color);
    color: white;
}

.btn-primary:hover {
    background-color: #1d4ed8;
}

.btn-secondary {
    background-color: var(--surface-light);
    color: var(--text-primary);
}

.btn-secondary:hover {
    background-color: #475569;
}

.btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

/* Results Panel */
.results-panel {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
}

.recommendations,
.diagnostic-history {
    background-color: var(--surface);
    border-radius: 0.5rem;
    padding: 1.5rem;
    border: 1px solid var(--surface-light);
}

.recommendations h2,
.diagnostic-history h2 {
    font-size: 1.125rem;
    margin-bottom: 1rem;
}

#recommendations-list {
    list-style: none;
    space-y: 0.5rem;
}

#recommendations-list li {
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--surface-light);
    color: var(--text-secondary);
}

#recommendations-list li:last-child {
    border-bottom: none;
}

#history-list {
    space-y: 0.5rem;
}

.history-item {
    padding: 0.5rem;
    background-color: var(--surface-light);
    border-radius: 0.25rem;
    font-size: 0.875rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

/* Alerts Panel */
.alerts-panel {
    background-color: var(--surface);
    border-radius: 0.5rem;
    padding: 1.5rem;
    border: 1px solid var(--surface-light);
}

.alerts-panel h2 {
    font-size: 1.125rem;
    margin-bottom: 1rem;
}

.alert-item {
    padding: 0.75rem;
    margin-bottom: 0.5rem;
    border-radius: 0.375rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.alert-critical {
    background-color: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: var(--danger-color);
}

.alert-warning {
    background-color: rgba(245, 158, 11, 0.1);
    border: 1px solid rgba(245, 158, 11, 0.3);
    color: var(--warning-color);
}

.no-alerts {
    color: var(--text-secondary);
    font-style: italic;
}

/* Responsive */
@media (max-width: 768px) {
    .metrics-grid {
        grid-template-columns: 1fr;
    }
    
    .results-panel {
        grid-template-columns: 1fr;
    }
    
    .controls,
    .monitoring-controls {
        flex-direction: column;
    }
    
    .btn {
        width: 100%;
        justify-content: center;
    }
}

/* Loading State */
.loading {
    opacity: 0.5;
    pointer-events: none;
}

.spinner {
    display: inline-block;
    width: 1rem;
    height: 1rem;
    border: 2px solid transparent;
    border-top-color: var(--primary-color);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}'''
    
    # Create JavaScript
    dashboard_js = '''// SuperSleuth Network Dashboard JavaScript

let monitoringActive = false;
let updateInterval = null;
let healthChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    updateStatus();
    updateMetrics();
    updateTime();
    
    // Set up periodic updates
    setInterval(updateTime, 1000);
    setInterval(updateStatus, 5000);
});

// Initialize charts
function initializeCharts() {
    const ctx = document.getElementById('health-chart').getContext('2d');
    healthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Health Score',
                data: [],
                borderColor: '#22c55e',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                borderWidth: 2,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                }
            }
        }
    });
}

// Update current time
function updateTime() {
    const now = new Date();
    document.getElementById('current-time').textContent = 
        now.toLocaleTimeString('en-US', { hour12: false });
}

// Update connection status
async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        const statusIndicator = document.getElementById('connection-status');
        const sessionInfo = document.getElementById('session-info');
        
        if (data.status === 'active') {
            statusIndicator.classList.remove('offline');
            sessionInfo.textContent = `Session: ${data.session_id}`;
        } else {
            sessionInfo.textContent = 'No Active Session';
        }
        
        // Update monitoring button
        const monitorBtn = document.getElementById('monitor-toggle');
        if (data.monitoring) {
            monitorBtn.textContent = '⏸️ Stop Monitoring';
            monitorBtn.classList.add('monitoring');
        } else {
            monitorBtn.textContent = '▶️ Start Monitoring';
            monitorBtn.classList.remove('monitoring');
        }
        
    } catch (error) {
        document.getElementById('connection-status').classList.add('offline');
        console.error('Failed to update status:', error);
    }
}

// Update metrics
async function updateMetrics() {
    try {
        const response = await fetch('/api/metrics');
        const metrics = await response.json();
        
        // Update metric values
        document.getElementById('health-score').textContent = metrics.network_health || '--';
        document.getElementById('device-count').textContent = metrics.active_devices || '--';
        document.getElementById('bandwidth-usage').textContent = metrics.bandwidth_usage || '--';
        document.getElementById('security-score').textContent = metrics.security_score || '--';
        
        // Update security level
        const securityLevel = document.getElementById('security-level');
        if (metrics.security_score >= 90) {
            securityLevel.textContent = 'Excellent';
            securityLevel.style.color = '#22c55e';
        } else if (metrics.security_score >= 70) {
            securityLevel.textContent = 'Good';
            securityLevel.style.color = '#f59e0b';
        } else {
            securityLevel.textContent = 'Needs Attention';
            securityLevel.style.color = '#ef4444';
        }
        
        // Update health chart
        if (healthChart && metrics.network_health) {
            const now = new Date().toLocaleTimeString('en-US', { 
                hour: '2-digit', 
                minute: '2-digit',
                hour12: false 
            });
            
            healthChart.data.labels.push(now);
            healthChart.data.datasets[0].data.push(metrics.network_health);
            
            // Keep only last 10 data points
            if (healthChart.data.labels.length > 10) {
                healthChart.data.labels.shift();
                healthChart.data.datasets[0].data.shift();
            }
            
            healthChart.update();
        }
        
        // Update current diagnostics
        updateCurrentDiagnostics();
        
    } catch (error) {
        console.error('Failed to update metrics:', error);
    }
}

// Update current diagnostics
async function updateCurrentDiagnostics() {
    try {
        const response = await fetch('/api/diagnostics/current');
        if (!response.ok) return;
        
        const data = await response.json();
        
        // Update recommendations
        const recList = document.getElementById('recommendations-list');
        if (data.recommendations && data.recommendations.length > 0) {
            recList.innerHTML = data.recommendations
                .map(rec => `<li>${rec}</li>`)
                .join('');
        }
        
        // Update health score if available
        if (data.health_score) {
            document.getElementById('health-score').textContent = data.health_score;
        }
        
    } catch (error) {
        console.error('Failed to update diagnostics:', error);
    }
}

// Run diagnostic
async function runDiagnostic(type) {
    const button = event.target;
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Running...';
    
    try {
        const response = await fetch('/api/diagnostics/run', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: type,
                client_name: 'Local Network',
                issue: 'Dashboard-initiated diagnostic'
            })
        });
        
        const result = await response.json();
        
        // Show notification
        showAlert(`${type.replace('_', ' ')} completed`, 'success');
        
        // Update history
        updateDiagnosticHistory();
        
        // Update metrics
        updateMetrics();
        
    } catch (error) {
        showAlert('Diagnostic failed: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.innerHTML = button.innerHTML.replace('<span class="spinner"></span> Running...', 
                                                   button.textContent);
    }
}

// Update diagnostic history
async function updateDiagnosticHistory() {
    try {
        const response = await fetch('/api/diagnostics/history');
        const history = await response.json();
        
        const historyList = document.getElementById('history-list');
        if (history.length > 0) {
            historyList.innerHTML = history
                .reverse()
                .map(item => `
                    <div class="history-item">
                        <span>${item.type.replace('_', ' ')}</span>
                        <span>${new Date(item.timestamp).toLocaleTimeString()}</span>
                    </div>
                `)
                .join('');
        }
        
    } catch (error) {
        console.error('Failed to update history:', error);
    }
}

// Toggle monitoring
async function toggleMonitoring() {
    const button = document.getElementById('monitor-toggle');
    button.disabled = true;
    
    try {
        const endpoint = monitoringActive ? '/api/monitoring/stop' : '/api/monitoring/start';
        const response = await fetch(endpoint, { method: 'POST' });
        const result = await response.json();
        
        monitoringActive = !monitoringActive;
        
        if (monitoringActive) {
            // Start real-time updates
            updateInterval = setInterval(updateMetrics, 2000);
            showAlert('Monitoring started', 'success');
        } else {
            // Stop real-time updates
            clearInterval(updateInterval);
            showAlert('Monitoring stopped', 'info');
        }
        
        updateStatus();
        
    } catch (error) {
        showAlert('Failed to toggle monitoring: ' + error.message, 'error');
    } finally {
        button.disabled = false;
    }
}

// Generate report
async function generateReport(audience) {
    const button = event.target;
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Generating...';
    
    try {
        const response = await fetch('/api/reports/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ audience: audience })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showAlert(`${audience} report generated successfully`, 'success');
            
            // Show preview in a modal or download
            if (confirm('Report generated. Download now?')) {
                // In a real implementation, would download the file
                console.log('Report path:', result.path);
            }
        }
        
    } catch (error) {
        showAlert('Report generation failed: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.innerHTML = button.innerHTML.replace('<span class="spinner"></span> Generating...', 
                                                   button.textContent);
    }
}

// Show alert
function showAlert(message, type = 'info') {
    const alertsList = document.getElementById('alerts-list');
    
    // Remove "no alerts" message if present
    const noAlerts = alertsList.querySelector('.no-alerts');
    if (noAlerts) {
        noAlerts.remove();
    }
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item alert-${type}`;
    alertDiv.textContent = message;
    
    alertsList.insertBefore(alertDiv, alertsList.firstChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
        
        // Show "no alerts" if empty
        if (alertsList.children.length === 0) {
            alertsList.innerHTML = '<p class="no-alerts">No active alerts</p>';
        }
    }, 5000);
}

// Start initial monitoring if needed
if (monitoringActive) {
    updateInterval = setInterval(updateMetrics, 2000);
}'''
    
    # Save templates
    with open(template_dir / 'dashboard.html', 'w') as f:
        f.write(dashboard_html)
    
    with open(static_dir / 'dashboard.css', 'w') as f:
        f.write(dashboard_css)
    
    with open(static_dir / 'dashboard.js', 'w') as f:
        f.write(dashboard_js)


# Main entry point
if __name__ == '__main__':
    # Create templates
    create_dashboard_templates()
    
    # Create and run dashboard
    dashboard = DashboardServer()
    dashboard.run()