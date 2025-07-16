#!/usr/bin/env python3
"""
Simple test of the topology and interference diagnostics module
"""

import sys
import os
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.diagnostics.topology_interference import TopologyInterferenceDiagnostics


def main():
    print("Testing Topology and Interference Diagnostics Module\n")
    
    diagnostics = TopologyInterferenceDiagnostics()
    
    # Test 1: WiFi Scanning
    print("1. Scanning WiFi networks...")
    try:
        networks = diagnostics.scan_wifi_networks()
        print(f"   Found {len(networks)} access points")
        
        if networks:
            # Show first 3 networks
            for i, (bssid, ap) in enumerate(list(networks.items())[:3]):
                print(f"   - {ap.ssid} ({ap.bssid}): Channel {ap.channel}, {ap.signal_strength} dBm")
        else:
            print("   No networks found (WiFi may be disabled or permissions needed)")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 2: Interference Analysis
    print("\n2. Analyzing interference...")
    try:
        interference = diagnostics.analyze_interference()
        print(f"   Co-channel conflicts: {len(interference['co_channel'])}")
        print(f"   Adjacent channel conflicts: {len(interference['adjacent_channel'])}")
        print(f"   Overlapping bandwidth: {len(interference['overlapping'])}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: Coverage Map
    print("\n3. Generating coverage map...")
    try:
        coverage = diagnostics.generate_coverage_map()
        for zone, aps in coverage.items():
            if aps:
                print(f"   {zone}: {len(aps)} APs")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 4: Channel Utilization
    print("\n4. Analyzing channel utilization...")
    try:
        utilization = diagnostics.analyze_channel_utilization()
        
        # Show 2.4GHz non-overlapping channels
        print("   2.4GHz non-overlapping channels:")
        for channel in [1, 6, 11]:
            if channel in utilization:
                info = utilization[channel]
                print(f"   Channel {channel}: {info['ap_count']} APs, Recommended: {info['recommended']}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 5: Network Topology (quick test)
    print("\n5. Discovering network topology (limited scan)...")
    try:
        # Get just local network info
        local_ip = diagnostics._get_local_ip()
        gateway_ip = diagnostics._get_default_gateway()
        
        print(f"   Local IP: {local_ip}")
        print(f"   Gateway: {gateway_ip}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 6: Recommendations
    print("\n6. Getting AP placement recommendations...")
    try:
        recommendations = diagnostics.recommend_ap_placement()
        
        if recommendations:
            print(f"   Found {len(recommendations)} recommendations:")
            for rec in recommendations[:2]:  # Show first 2
                print(f"   - {rec['severity']}: {rec['issue']}")
        else:
            print("   No specific recommendations at this time")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\nTest complete!")


if __name__ == "__main__":
    main()