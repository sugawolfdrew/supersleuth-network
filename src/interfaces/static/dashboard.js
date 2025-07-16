// SuperSleuth Network Dashboard JavaScript

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
}