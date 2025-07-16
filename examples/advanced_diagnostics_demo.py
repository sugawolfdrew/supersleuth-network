#!/usr/bin/env python3
"""
Advanced Diagnostics Demo for SuperSleuth Network

This script demonstrates how Claude Code would use the advanced diagnostics
functions for various troubleshooting scenarios.
"""

import time
import json
from datetime import datetime
from typing import Dict, Any

# Import the advanced diagnostics functions
try:
    from src.diagnostics.advanced_diagnostics import (
        AdvancedDiagnostics,
        process_analysis,
        system_bottleneck_detection,
        historical_trend_analysis,
        anomaly_detection,
        diagnose_slow_system
    )
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from src.diagnostics.advanced_diagnostics import (
        AdvancedDiagnostics,
        process_analysis,
        system_bottleneck_detection,
        historical_trend_analysis,
        anomaly_detection,
        diagnose_slow_system
    )


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'=' * 80}")
    print(f" {title}")
    print('=' * 80)


def print_json(data: Dict[str, Any]):
    """Pretty print JSON data"""
    print(json.dumps(data, indent=2, default=str))


def scenario_server_slow():
    """Scenario 1: Server is running slow"""
    print_section("SCENARIO 1: Server is running slow")
    print("\nClaude Code investigating slow server performance...")
    
    # First, check for system bottlenecks
    print("\n1. Checking for system bottlenecks:")
    bottlenecks = system_bottleneck_detection()
    
    if bottlenecks.get('bottlenecks'):
        print(f"\nFound {len(bottlenecks['bottlenecks'])} bottlenecks:")
        for b in bottlenecks['bottlenecks']:
            print(f"  - {b['type']}: {b['message']} (Severity: {b['severity']})")
            print(f"    Recommendation: {b['recommendation']}")
    else:
        print("  No significant bottlenecks detected")
    
    # Analyze resource-intensive processes
    print("\n2. Analyzing top resource-consuming processes:")
    processes = process_analysis(top_n=5)
    
    print(f"\nTop CPU consumers:")
    for i, proc in enumerate(processes['top_cpu_consumers'][:3], 1):
        print(f"  {i}. {proc['name']} (PID: {proc['pid']}) - {proc['cpu_percent']:.1f}% CPU")
        if proc['connections']:
            print(f"     Network connections: {len(proc['connections'])}")
    
    print(f"\nTop memory consumers:")
    for i, proc in enumerate(processes['top_memory_consumers'][:3], 1):
        print(f"  {i}. {proc['name']} (PID: {proc['pid']}) - {proc['memory_rss_mb']:.1f} MB")
    
    # Use the quick diagnostic function
    print("\n3. Running comprehensive slow system diagnosis:")
    diagnosis = diagnose_slow_system()
    
    if diagnosis['recommendations']:
        print("\nRecommendations:")
        for rec in diagnosis['recommendations']:
            print(f"  • {rec}")
    
    # Return findings for Claude Code
    return {
        'bottlenecks': bottlenecks['bottlenecks'],
        'top_cpu_process': processes['top_cpu_consumers'][0] if processes['top_cpu_consumers'] else None,
        'recommendations': diagnosis['recommendations']
    }


def scenario_bandwidth_hog():
    """Scenario 2: Something is using all the bandwidth"""
    print_section("SCENARIO 2: Something is using all the bandwidth")
    print("\nClaude Code investigating bandwidth consumption...")
    
    # Check processes with network connections
    print("\n1. Identifying processes with network activity:")
    processes = process_analysis(top_n=20)
    
    # Filter and sort by network connections
    network_active = [p for p in processes['top_network_users'] if p['connections']]
    
    print(f"\nTop network-active processes:")
    for i, proc in enumerate(network_active[:5], 1):
        print(f"  {i}. {proc['name']} (PID: {proc['pid']})")
        print(f"     Connections: {len(proc['connections'])}")
        
        # Show connection details
        for j, conn in enumerate(proc['connections'][:3], 1):
            if conn['remote_addr']:
                print(f"       {j}. {conn['type']} → {conn['remote_addr']} ({conn['status']})")
    
    # Check for anomalies
    print("\n2. Checking for network anomalies:")
    anomalies = anomaly_detection(real_time=True)
    
    network_anomalies = [a for a in anomalies['anomalies'] 
                        if a['type'] in ['excessive_connections', 'unusual_ports', 'port_scan']]
    
    if network_anomalies:
        print(f"\nNetwork anomalies detected:")
        for anomaly in network_anomalies:
            print(f"  - {anomaly['message']} (Severity: {anomaly['severity']})")
    else:
        print("  No network anomalies detected")
    
    # Check system metrics
    print("\n3. Checking network bottlenecks:")
    bottlenecks = system_bottleneck_detection()
    network_bottleneck = next((b for b in bottlenecks['bottlenecks'] 
                              if b['type'] == 'network_drops'), None)
    
    if network_bottleneck:
        print(f"  Network issue: {network_bottleneck['message']}")
    
    return {
        'bandwidth_hogs': network_active[:3],
        'network_anomalies': network_anomalies,
        'total_connections': sum(len(p['connections']) for p in processes['top_network_users'])
    }


def scenario_performance_degraded():
    """Scenario 3: System performance degraded after update"""
    print_section("SCENARIO 3: System performance degraded after update")
    print("\nClaude Code analyzing performance degradation...")
    
    # Create an advanced diagnostics instance to build history
    diag = AdvancedDiagnostics(history_size=20)
    
    # Set initial baseline (simulating pre-update state)
    print("\n1. Setting performance baseline:")
    diag.set_baseline()
    print("  Baseline metrics captured")
    
    # Simulate some activity and collect metrics
    print("\n2. Collecting performance metrics over time...")
    for i in range(10):
        diag._take_snapshot()
        time.sleep(0.5)
        print(f"  Snapshot {i+1}/10 collected")
    
    # Analyze trends
    print("\n3. Analyzing performance trends:")
    trends = diag.historical_trend_analysis(duration_minutes=1)
    
    # Look for degrading metrics
    degrading_metrics = []
    for metric, trend_data in trends['trends'].items():
        if trend_data['trend'] == 'increasing' and 'percent' in metric:
            degrading_metrics.append({
                'metric': metric,
                'change': trend_data['change_percent'],
                'current': trend_data['current_value']
            })
    
    if degrading_metrics:
        print(f"\nMetrics showing degradation:")
        for metric in sorted(degrading_metrics, key=lambda x: abs(x['change']), reverse=True):
            print(f"  - {metric['metric']}: {metric['change']:+.1f}% "
                  f"(current: {metric['current']:.1f})")
    
    # Check for anomalies
    print("\n4. Detecting anomalies in system behavior:")
    anomalies = diag.anomaly_detection(real_time=True)
    
    if anomalies['anomalies']:
        print(f"\nAnomalies detected ({len(anomalies['anomalies'])} total):")
        for anomaly in anomalies['anomalies'][:5]:
            print(f"  - {anomaly['type']}: {anomaly['message']}")
    
    # Compare with baseline
    print("\n5. Comparing with baseline performance:")
    comparison = trends.get('baseline_comparison', {})
    
    if comparison.get('comparisons'):
        deviations = []
        for metric, comp in comparison['comparisons'].items():
            if abs(comp['deviation_percent']) > 20:
                deviations.append({
                    'metric': metric,
                    'deviation': comp['deviation_percent'],
                    'baseline': comp['baseline_mean'],
                    'current': comp['current_value']
                })
        
        if deviations:
            print("\nSignificant deviations from baseline:")
            for dev in sorted(deviations, key=lambda x: abs(x['deviation']), reverse=True):
                print(f"  - {dev['metric']}: {dev['deviation']:+.1f}% deviation")
                print(f"    Baseline: {dev['baseline']:.1f}, Current: {dev['current']:.1f}")
    
    return {
        'degrading_metrics': degrading_metrics,
        'anomaly_count': len(anomalies['anomalies']),
        'baseline_deviations': len(deviations) if 'deviations' in locals() else 0
    }


def scenario_unusual_activity():
    """Scenario 4: Unusual activity detected"""
    print_section("SCENARIO 4: Unusual activity detected")
    print("\nClaude Code investigating suspicious system activity...")
    
    # Full anomaly detection
    print("\n1. Running comprehensive anomaly detection:")
    anomalies = anomaly_detection(real_time=True)
    
    # Categorize anomalies
    by_severity = {
        'high': [],
        'medium': [],
        'low': []
    }
    
    for anomaly in anomalies['anomalies']:
        severity = anomaly.get('severity', 'low')
        by_severity[severity].append(anomaly)
    
    # Report high severity first
    if by_severity['high']:
        print(f"\nHIGH SEVERITY anomalies ({len(by_severity['high'])}):")
        for anomaly in by_severity['high']:
            print(f"  ! {anomaly['type']}: {anomaly['message']}")
            if 'details' in anomaly:
                for key, value in anomaly['details'].items():
                    print(f"    - {key}: {value}")
    
    # Check for suspicious processes
    print("\n2. Analyzing process behavior:")
    processes = process_analysis(top_n=50)
    
    # Look for suspicious patterns
    suspicious_patterns = []
    
    # Check for processes with many connections
    for proc in processes['top_network_users']:
        if len(proc['connections']) > 50:
            suspicious_patterns.append({
                'type': 'excessive_connections',
                'process': proc['name'],
                'pid': proc['pid'],
                'connections': len(proc['connections'])
            })
    
    # Check for hidden processes (no parent)
    orphan_processes = [p for p in processes['top_cpu_consumers'] + processes['top_memory_consumers']
                       if p.get('parent_pid') is None and p['name'] not in ['kernel_task', 'init']]
    
    for proc in orphan_processes[:5]:
        suspicious_patterns.append({
            'type': 'orphan_process',
            'process': proc['name'],
            'pid': proc['pid']
        })
    
    if suspicious_patterns:
        print(f"\nSuspicious patterns detected:")
        for pattern in suspicious_patterns:
            print(f"  - {pattern['type']}: {pattern['process']} (PID: {pattern['pid']})")
    
    # Historical analysis for behavior changes
    print("\n3. Checking for behavioral changes:")
    diag = AdvancedDiagnostics()
    
    # Take several snapshots
    for _ in range(5):
        diag._take_snapshot()
        time.sleep(1)
    
    trends = diag.historical_trend_analysis(duration_minutes=5)
    
    # Look for sudden changes
    sudden_changes = []
    for metric, trend_data in trends['trends'].items():
        if trend_data.get('anomalies'):
            sudden_changes.append({
                'metric': metric,
                'anomaly_count': len(trend_data['anomalies']),
                'current_value': trend_data['current_value']
            })
    
    if sudden_changes:
        print(f"\nMetrics with sudden changes:")
        for change in sudden_changes:
            print(f"  - {change['metric']}: {change['anomaly_count']} anomalies detected")
    
    # Generate security recommendations
    recommendations = []
    
    if by_severity['high']:
        recommendations.append("Immediate investigation required for high-severity anomalies")
    
    if any(a['type'] == 'port_scan' for a in anomalies['anomalies']):
        recommendations.append("Possible port scanning detected - check firewall logs")
    
    if any(a['type'] == 'suspicious_process' for a in anomalies['anomalies']):
        recommendations.append("Suspicious processes found - verify legitimacy and scan for malware")
    
    if suspicious_patterns:
        recommendations.append("Review processes with unusual behavior patterns")
    
    print("\n4. Security recommendations:")
    for rec in recommendations:
        print(f"  • {rec}")
    
    return {
        'total_anomalies': len(anomalies['anomalies']),
        'high_severity_count': len(by_severity['high']),
        'suspicious_patterns': len(suspicious_patterns),
        'recommendations': recommendations
    }


def main():
    """Run all demo scenarios"""
    print("Advanced Diagnostics Demo for SuperSleuth Network")
    print("=" * 80)
    print("\nThis demo shows how Claude Code would use advanced diagnostics")
    print("to troubleshoot various system issues.\n")
    
    scenarios = [
        ("Server is running slow", scenario_server_slow),
        ("Something is using all the bandwidth", scenario_bandwidth_hog),
        ("System performance degraded after update", scenario_performance_degraded),
        ("Unusual activity detected", scenario_unusual_activity)
    ]
    
    results = {}
    
    for name, scenario_func in scenarios:
        try:
            print(f"\nRunning scenario: {name}")
            results[name] = scenario_func()
            print(f"\nScenario completed successfully")
            time.sleep(2)  # Pause between scenarios
        except Exception as e:
            print(f"\nError in scenario '{name}': {e}")
            results[name] = {'error': str(e)}
    
    # Summary
    print_section("DEMO SUMMARY")
    print("\nScenario Results:")
    for scenario, result in results.items():
        if 'error' in result:
            print(f"\n  {scenario}: ERROR - {result['error']}")
        else:
            print(f"\n  {scenario}: COMPLETED")
            # Print key findings
            for key, value in result.items():
                if isinstance(value, (int, float)):
                    print(f"    - {key}: {value}")
                elif isinstance(value, list) and value:
                    print(f"    - {key}: {len(value)} items")
    
    print("\n" + "=" * 80)
    print("Demo completed. Advanced diagnostics ready for use by Claude Code.")
    print("=" * 80)


if __name__ == "__main__":
    main()