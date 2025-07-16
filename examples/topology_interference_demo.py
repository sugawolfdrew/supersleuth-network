#!/usr/bin/env python3
"""
Topology and Interference Diagnostics Demo

This demo shows how to diagnose common WiFi and network issues using
the SuperSleuth Network topology and interference diagnostics module.
"""

import json
import time
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics.topology_interference import TopologyInterferenceDiagnostics


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'=' * 60}")
    print(f"{title.center(60)}")
    print(f"{'=' * 60}\n")


def print_subsection(title: str):
    """Print a formatted subsection header"""
    print(f"\n{'-' * 40}")
    print(f"{title}")
    print(f"{'-' * 40}")


def scenario_slow_wifi():
    """Diagnose 'WiFi is slow in conference room' scenario"""
    print_section("Scenario: WiFi is Slow in Conference Room")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    print("Scanning WiFi networks...")
    networks = diagnostics.scan_wifi_networks()
    print(f"Found {len(networks)} access points")
    
    # Diagnose slow WiFi issue
    diagnosis = diagnostics.diagnose_issue("slow_wifi")
    
    print_subsection("Findings")
    for finding in diagnosis["findings"]:
        print(f"• {finding}")
    
    print_subsection("Recommendations")
    for rec in diagnosis["recommendations"]:
        print(f"✓ {rec}")
    
    # Show interference analysis
    print_subsection("Interference Analysis")
    interference = diagnostics.analyze_interference()
    
    if interference["co_channel"]:
        print(f"\nCo-channel interference detected:")
        for item in interference["co_channel"][:3]:  # Show first 3
            print(f"  • Channel {item['channel']}: {item['ap1']} ({item['ap1_signal']} dBm) ↔ {item['ap2']} ({item['ap2_signal']} dBm)")
            print(f"    Severity: {item['severity']}")
    
    if interference["adjacent_channel"]:
        print(f"\nAdjacent channel interference:")
        for item in interference["adjacent_channel"][:3]:
            print(f"  • Channels {item['channel1']}-{item['channel2']}: {item['ap1']} ↔ {item['ap2']}")
    
    # Show channel utilization
    print_subsection("Channel Utilization (2.4GHz)")
    channel_util = diagnostics.analyze_channel_utilization()
    
    for channel in [1, 6, 11]:  # Non-overlapping channels
        if channel in channel_util:
            info = channel_util[channel]
            status = "✓ Recommended" if info["recommended"] else "✗ Crowded"
            print(f"Channel {channel}: {info['ap_count']} APs, Strongest: {info['strongest_signal']} dBm {status}")
    
    # Show signal quality for nearby APs
    print_subsection("Signal Quality Analysis")
    
    # Get top 3 strongest signals
    strongest_aps = sorted(networks.values(), key=lambda x: x.signal_strength, reverse=True)[:3]
    
    for ap in strongest_aps:
        quality = diagnostics.analyze_signal_quality(ap.bssid)
        if quality:
            print(f"\n{ap.ssid} (Channel {ap.channel}):")
            print(f"  Signal: {ap.signal_strength} dBm")
            print(f"  SNR: {quality.snr:.1f} dB")
            print(f"  Estimated Speed: {quality.tx_rate} Mbps")
            print(f"  Retry Rate: {quality.retry_rate:.1f}%")
            print(f"  Error Rate: {quality.error_rate:.1f}%")


def scenario_random_disconnections():
    """Diagnose 'Random disconnections' scenario"""
    print_section("Scenario: Random Disconnections")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    print("Analyzing network stability...")
    networks = diagnostics.scan_wifi_networks()
    
    # Diagnose disconnection issues
    diagnosis = diagnostics.diagnose_issue("random_disconnections")
    
    print_subsection("Findings")
    for finding in diagnosis["findings"]:
        print(f"• {finding}")
    
    print_subsection("Recommendations")
    for rec in diagnosis["recommendations"]:
        print(f"✓ {rec}")
    
    # Check for roaming issues
    print_subsection("Roaming Analysis")
    
    # Group APs by SSID
    ssid_groups = {}
    for ap in networks.values():
        if ap.ssid not in ssid_groups:
            ssid_groups[ap.ssid] = []
        ssid_groups[ap.ssid].append(ap)
    
    for ssid, aps in ssid_groups.items():
        if len(aps) > 1:
            print(f"\n{ssid}: {len(aps)} access points")
            for ap in sorted(aps, key=lambda x: x.signal_strength, reverse=True):
                print(f"  • {ap.bssid} - Channel {ap.channel}: {ap.signal_strength} dBm")
            
            # Check for roaming issues
            signals = [ap.signal_strength for ap in aps]
            if max(signals) - min(signals) < 15:
                print("  ⚠️  Similar signal strengths may cause roaming issues")


def scenario_dead_zones():
    """Diagnose 'Can't connect in certain areas' scenario"""
    print_section("Scenario: Can't Connect in Certain Areas")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    print("Mapping WiFi coverage...")
    networks = diagnostics.scan_wifi_networks()
    
    # Generate coverage map
    coverage = diagnostics.generate_coverage_map()
    
    print_subsection("Coverage Analysis")
    
    print(f"Excellent Coverage (-50 dBm or better): {len(coverage['excellent'])} APs")
    print(f"Good Coverage (-50 to -60 dBm): {len(coverage['good'])} APs")
    print(f"Fair Coverage (-60 to -70 dBm): {len(coverage['fair'])} APs")
    print(f"Weak Coverage (-70 to -80 dBm): {len(coverage['weak'])} APs")
    print(f"Dead Zones (-80 dBm or worse): {len(coverage['dead_zones'])} APs")
    
    # Show dead zones
    if coverage['dead_zones']:
        print_subsection("Dead Zone Details")
        for zone in coverage['dead_zones']:
            print(f"• {zone['ssid']} - Channel {zone['channel']}: {zone['signal']} dBm")
    
    # Get placement recommendations
    print_subsection("AP Placement Recommendations")
    recommendations = diagnostics.recommend_ap_placement()
    
    for rec in recommendations:
        print(f"\n{rec['severity'].upper()}: {rec['issue']}")
        print(f"  Recommendation: {rec['recommendation']}")
        print(f"  Details: {rec['details']}")


def scenario_time_based_slowdown():
    """Diagnose 'Network slows down at certain times' scenario"""
    print_section("Scenario: Network Slows Down at Certain Times")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    print("Monitoring network over time...")
    print("(In production, this would track metrics over hours/days)")
    
    # Simulate time-based monitoring
    samples = []
    for i in range(3):
        print(f"\nSample {i+1}/3...")
        networks = diagnostics.scan_wifi_networks()
        
        # Track channel utilization
        channel_util = diagnostics.analyze_channel_utilization()
        
        sample = {
            "time": time.strftime("%H:%M:%S"),
            "total_aps": len(networks),
            "channels_used": len([c for c, info in channel_util.items() if info["ap_count"] > 0]),
            "avg_signal": sum(ap.signal_strength for ap in networks.values()) / len(networks) if networks else 0
        }
        samples.append(sample)
        
        time.sleep(2)  # Wait between samples
    
    print_subsection("Time-Based Analysis")
    for sample in samples:
        print(f"{sample['time']}: {sample['total_aps']} APs on {sample['channels_used']} channels, Avg Signal: {sample['avg_signal']:.1f} dBm")
    
    # Diagnose time-based issues
    diagnosis = diagnostics.diagnose_issue("time_based_slowdown")
    
    print_subsection("Findings")
    for finding in diagnosis["findings"]:
        print(f"• {finding}")
    
    print_subsection("Recommendations")
    for rec in diagnosis["recommendations"]:
        print(f"✓ {rec}")


def show_network_topology():
    """Display network topology discovery"""
    print_section("Network Topology Discovery")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    print("Discovering network topology...")
    print("(This may take a moment...)")
    
    topology = diagnostics.discover_network_topology()
    
    print(f"\nDiscovered {len(topology)} network nodes")
    
    # Group by device type
    device_types = {}
    for node in topology.values():
        if node.device_type not in device_types:
            device_types[node.device_type] = []
        device_types[node.device_type].append(node)
    
    print_subsection("Network Devices by Type")
    for device_type, nodes in device_types.items():
        print(f"\n{device_type.upper()} ({len(nodes)} devices):")
        for node in nodes[:5]:  # Show first 5 of each type
            print(f"  • {node.ip_address} - {node.hostname}")
            if node.latency > 0:
                print(f"    Latency: {node.latency:.1f} ms")
    
    # Show network path
    print_subsection("Network Paths")
    gateway = next((n for n in topology.values() if n.device_type == "router"), None)
    
    if gateway:
        print(f"Gateway: {gateway.ip_address} ({gateway.hostname})")
        
        # Show paths to other devices
        for node in list(topology.values())[:3]:
            if node != gateway and node.hop_count > 0:
                print(f"\nPath to {node.ip_address}:")
                print(f"  Hops: {node.hop_count}")
                print(f"  Latency: {node.latency:.1f} ms")


def generate_full_report():
    """Generate comprehensive diagnostic report"""
    print_section("Comprehensive Network Diagnostic Report")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    print("Generating full diagnostic report...")
    print("This includes:")
    print("  • WiFi network scanning")
    print("  • Interference analysis") 
    print("  • Coverage mapping")
    print("  • Topology discovery")
    print("  • Recommendations")
    
    report = diagnostics.generate_report()
    
    # Save report to file
    report_file = "network_diagnostic_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {report_file}")
    
    # Display summary
    print_subsection("Report Summary")
    print(f"Scan Time: {report['timestamp']}")
    print(f"Total APs Detected: {report['summary']['total_aps_detected']}")
    print(f"Channels in Use: {len(report['summary']['channels_in_use'])}")
    print(f"Network Nodes: {report['summary']['topology_nodes']}")
    
    # Show top recommendations
    if report['recommendations']:
        print_subsection("Top Recommendations")
        for rec in report['recommendations'][:3]:
            print(f"\n{rec['severity'].upper()}: {rec['issue']}")
            print(f"  → {rec['recommendation']}")


def main():
    """Main demo function"""
    print("=" * 60)
    print("SuperSleuth Network - Topology & Interference Diagnostics Demo")
    print("=" * 60)
    
    scenarios = {
        "1": ("WiFi is slow in conference room", scenario_slow_wifi),
        "2": ("Random disconnections", scenario_random_disconnections),
        "3": ("Can't connect in certain areas", scenario_dead_zones),
        "4": ("Network slows down at certain times", scenario_time_based_slowdown),
        "5": ("Show network topology", show_network_topology),
        "6": ("Generate full diagnostic report", generate_full_report),
    }
    
    while True:
        print("\nSelect a scenario to diagnose:")
        for key, (desc, _) in scenarios.items():
            print(f"{key}. {desc}")
        print("0. Exit")
        
        choice = input("\nEnter your choice (0-6): ").strip()
        
        if choice == "0":
            print("\nExiting...")
            break
        elif choice in scenarios:
            _, scenario_func = scenarios[choice]
            try:
                scenario_func()
            except Exception as e:
                print(f"\nError running scenario: {e}")
                print("Some features may require elevated privileges (sudo) or specific network configurations.")
        else:
            print("Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()