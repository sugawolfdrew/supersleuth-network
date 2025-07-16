#!/usr/bin/env python3
"""
Example of integrating the Topology and Interference Diagnostics module
with SuperSleuth Network's existing monitoring capabilities.
"""

import sys
import os
import time
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics.topology_interference import TopologyInterferenceDiagnostics
from src.network_monitor import NetworkMonitor
from src.alert_manager import AlertManager, Alert


def integrate_wifi_diagnostics_with_monitoring():
    """Example of using WiFi diagnostics with network monitoring"""
    
    print("=== SuperSleuth Network - Integrated WiFi Diagnostics ===\n")
    
    # Initialize components
    topology_diag = TopologyInterferenceDiagnostics()
    network_monitor = NetworkMonitor()
    alert_manager = AlertManager()
    
    # 1. Run WiFi diagnostics
    print("1. Running WiFi diagnostics...")
    wifi_networks = topology_diag.scan_wifi_networks()
    print(f"   Found {len(wifi_networks)} WiFi networks")
    
    # 2. Analyze interference
    print("\n2. Analyzing interference...")
    interference = topology_diag.analyze_interference()
    
    # Create alerts for critical interference
    critical_interference = [i for i in interference["co_channel"] if i["severity"] == "critical"]
    if critical_interference:
        alert = Alert(
            title="Critical WiFi Interference Detected",
            description=f"Found {len(critical_interference)} critical co-channel interference issues",
            severity="high",
            source="WiFi Diagnostics",
            details={
                "interference_count": len(critical_interference),
                "affected_channels": list(set(i["channel"] for i in critical_interference))
            }
        )
        alert_manager.add_alert(alert)
        print(f"   ⚠️  Created alert for critical interference")
    
    # 3. Check coverage quality
    print("\n3. Checking coverage quality...")
    coverage = topology_diag.generate_coverage_map()
    
    # Alert on dead zones
    if coverage["dead_zones"]:
        alert = Alert(
            title="WiFi Dead Zones Detected",
            description=f"{len(coverage['dead_zones'])} areas with very poor WiFi coverage",
            severity="warning",
            source="WiFi Diagnostics",
            details={
                "dead_zone_count": len(coverage["dead_zones"]),
                "weak_coverage_count": len(coverage["weak"])
            }
        )
        alert_manager.add_alert(alert)
        print(f"   ⚠️  Found {len(coverage['dead_zones'])} dead zones")
    
    # 4. Get current connection quality
    print("\n4. Analyzing current connection quality...")
    
    # Find the strongest signal (likely connected AP)
    if wifi_networks:
        strongest_ap = max(wifi_networks.values(), key=lambda x: x.signal_strength)
        quality = topology_diag.analyze_signal_quality(strongest_ap.bssid)
        
        if quality:
            print(f"   Connected to: {strongest_ap.ssid}")
            print(f"   Signal: {strongest_ap.signal_strength} dBm")
            print(f"   SNR: {quality.snr:.1f} dB")
            print(f"   Estimated speed: {quality.tx_rate} Mbps")
            
            # Alert if poor quality
            if quality.snr < 20:
                alert = Alert(
                    title="Poor WiFi Signal Quality",
                    description=f"Low SNR detected ({quality.snr:.1f} dB)",
                    severity="warning",
                    source="WiFi Diagnostics",
                    details={
                        "ssid": strongest_ap.ssid,
                        "snr": quality.snr,
                        "retry_rate": quality.retry_rate,
                        "error_rate": quality.error_rate
                    }
                )
                alert_manager.add_alert(alert)
    
    # 5. Monitor network performance with WiFi context
    print("\n5. Monitoring network performance...")
    
    # Run a quick performance test
    network_monitor.measure_performance()
    time.sleep(2)  # Let it collect some data
    
    metrics = network_monitor.get_current_metrics()
    
    # Correlate network issues with WiFi problems
    if metrics and metrics.get("bandwidth", 0) < 10:  # Less than 10 Mbps
        # Check if it's WiFi-related
        channel_util = topology_diag.analyze_channel_utilization()
        congested_channels = [ch for ch, info in channel_util.items() 
                            if info["ap_count"] > 3 and info["frequency"] == "2.4GHz"]
        
        if congested_channels:
            print(f"   ⚠️  Low bandwidth may be due to channel congestion")
            print(f"   Congested channels: {congested_channels}")
            
            # Create correlated alert
            alert = Alert(
                title="Low Bandwidth - WiFi Congestion Detected",
                description="Network performance degraded due to WiFi channel congestion",
                severity="high",
                source="Network Monitor + WiFi Diagnostics",
                details={
                    "bandwidth": metrics.get("bandwidth", 0),
                    "congested_channels": congested_channels,
                    "recommendation": "Switch to 5GHz or less congested channel"
                }
            )
            alert_manager.add_alert(alert)
    
    # 6. Generate comprehensive report
    print("\n6. Generating diagnostic report...")
    
    # Get topology info
    topology = topology_diag.discover_network_topology()
    
    # Create integrated report
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "network_metrics": {
            "bandwidth": metrics.get("bandwidth", 0) if metrics else 0,
            "latency": metrics.get("latency", 0) if metrics else 0,
            "packet_loss": metrics.get("packet_loss", 0) if metrics else 0
        },
        "wifi_summary": {
            "total_networks": len(wifi_networks),
            "interference_issues": len(interference["co_channel"]),
            "dead_zones": len(coverage["dead_zones"]),
            "congested_channels": len([ch for ch, info in channel_util.items() 
                                     if info["ap_count"] > 3])
        },
        "topology_summary": {
            "devices_discovered": len(topology),
            "gateway": next((n.ip_address for n in topology.values() 
                           if n.device_type == "router"), "Unknown")
        },
        "alerts_generated": len(alert_manager.get_active_alerts())
    }
    
    # Save report
    report_file = "integrated_diagnostics_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"   Report saved to: {report_file}")
    
    # 7. Show recommendations
    print("\n7. Recommendations:")
    recommendations = topology_diag.recommend_ap_placement()
    
    for i, rec in enumerate(recommendations[:3], 1):
        print(f"   {i}. [{rec['severity']}] {rec['recommendation']}")
    
    # Show active alerts
    print(f"\n8. Active Alerts ({len(alert_manager.get_active_alerts())}):")
    for alert in alert_manager.get_active_alerts()[:5]:
        print(f"   • [{alert.severity}] {alert.title}")
    
    # Cleanup
    network_monitor.stop()
    
    print("\n✓ Integrated diagnostics complete!")


def continuous_wifi_monitoring():
    """Example of continuous WiFi monitoring with alerts"""
    
    print("=== Continuous WiFi Monitoring Mode ===\n")
    print("Monitoring WiFi environment for changes...")
    print("Press Ctrl+C to stop\n")
    
    topology_diag = TopologyInterferenceDiagnostics()
    alert_manager = AlertManager()
    
    previous_networks = {}
    previous_interference = {"co_channel": [], "adjacent_channel": [], "overlapping": []}
    
    try:
        while True:
            # Scan networks
            current_networks = topology_diag.scan_wifi_networks()
            
            # Check for new networks
            new_networks = set(current_networks.keys()) - set(previous_networks.keys())
            if new_networks:
                print(f"\n🆕 New networks detected: {len(new_networks)}")
                for bssid in list(new_networks)[:3]:
                    ap = current_networks[bssid]
                    print(f"   • {ap.ssid} (Channel {ap.channel}, {ap.signal_strength} dBm)")
            
            # Check for disappeared networks
            lost_networks = set(previous_networks.keys()) - set(current_networks.keys())
            if lost_networks:
                print(f"\n🚫 Networks disappeared: {len(lost_networks)}")
            
            # Check for signal changes
            for bssid, ap in current_networks.items():
                if bssid in previous_networks:
                    prev_ap = previous_networks[bssid]
                    signal_change = ap.signal_strength - prev_ap.signal_strength
                    
                    if abs(signal_change) > 10:
                        direction = "improved" if signal_change > 0 else "degraded"
                        print(f"\n📶 Signal {direction}: {ap.ssid} ({signal_change:+d} dBm)")
            
            # Check interference changes
            current_interference = topology_diag.analyze_interference()
            
            new_conflicts = len(current_interference["co_channel"]) - len(previous_interference["co_channel"])
            if new_conflicts > 0:
                print(f"\n⚠️  New interference detected: {new_conflicts} additional conflicts")
                
                alert = Alert(
                    title="Increased WiFi Interference",
                    description=f"{new_conflicts} new co-channel conflicts detected",
                    severity="warning",
                    source="WiFi Monitor"
                )
                alert_manager.add_alert(alert)
            
            # Update previous state
            previous_networks = current_networks
            previous_interference = current_interference
            
            # Show summary line
            print(f"\r📊 Networks: {len(current_networks)} | "
                  f"Conflicts: {len(current_interference['co_channel'])} | "
                  f"Time: {time.strftime('%H:%M:%S')}", end='', flush=True)
            
            # Wait before next scan
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")


def main():
    """Main example runner"""
    print("SuperSleuth Network - Topology & Interference Integration Examples\n")
    
    examples = {
        "1": ("Run integrated diagnostics", integrate_wifi_diagnostics_with_monitoring),
        "2": ("Start continuous WiFi monitoring", continuous_wifi_monitoring),
    }
    
    print("Select an example:")
    for key, (desc, _) in examples.items():
        print(f"{key}. {desc}")
    print("0. Exit")
    
    choice = input("\nEnter your choice (0-2): ").strip()
    
    if choice == "0":
        print("Exiting...")
    elif choice in examples:
        _, example_func = examples[choice]
        try:
            example_func()
        except Exception as e:
            print(f"\nError: {e}")
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()