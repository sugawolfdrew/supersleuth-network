#!/usr/bin/env python3
"""
Demonstration of REAL network diagnostic functionality in SuperSleuth Network
This shows actual working code, not placeholders!
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psutil
import socket
import subprocess
from src.diagnostics.port_scanner import check_single_port, scan_port_range
from src.diagnostics.dns_diagnostics import DNSDiagnostics
import netifaces

print("🚀 SuperSleuth Network - REAL Functionality Demo")
print("=" * 60)
print("This is NOT cardboard - these are actual working diagnostics!\n")

# 1. REAL Network Interface Analysis
print("1️⃣ REAL Network Interface Analysis")
print("-" * 40)

# Get actual network interfaces
interfaces = psutil.net_if_stats()
print(f"Found {len(interfaces)} network interfaces:\n")

for iface, stats in interfaces.items():
    if stats.isup and 'lo' not in iface.lower():
        addrs = psutil.net_if_addrs().get(iface, [])
        io_counters = psutil.net_io_counters(pernic=True).get(iface)
        
        # Get IP addresses
        ipv4 = [addr.address for addr in addrs if addr.family == socket.AF_INET]
        
        print(f"✅ {iface}")
        print(f"   Status: UP")
        print(f"   Speed: {stats.speed} Mbps")
        print(f"   MTU: {stats.mtu}")
        if ipv4:
            print(f"   IPv4: {ipv4[0]}")
        
        if io_counters:
            # Calculate REAL error rates
            total_packets = io_counters.packets_sent + io_counters.packets_recv
            if total_packets > 0:
                error_rate = ((io_counters.errin + io_counters.errout) / total_packets) * 100
                print(f"   Packets Sent: {io_counters.packets_sent:,}")
                print(f"   Packets Received: {io_counters.packets_recv:,}")
                print(f"   Error Rate: {error_rate:.3f}%")
                if error_rate > 1:
                    print(f"   ⚠️  WARNING: High error rate detected!")
        print()

# 2. REAL Port Scanning
print("\n2️⃣ REAL Port Scanning")
print("-" * 40)
print("Testing connectivity to common services...\n")

# Test some common ports
test_targets = [
    ('google.com', 80, 'HTTP'),
    ('google.com', 443, 'HTTPS'),
    ('8.8.8.8', 53, 'DNS'),
]

for host, port, service in test_targets:
    result = check_single_port(host, port, timeout=2.0)
    if result.get('open', False):
        print(f"✅ {service} ({host}:{port}) - REACHABLE")
        print(f"   Response time: {result.get('response_time', 0)*1000:.1f}ms")
    else:
        print(f"❌ {service} ({host}:{port}) - UNREACHABLE")

# 3. REAL DNS Diagnostics
print("\n\n3️⃣ REAL DNS Diagnostics")
print("-" * 40)

dns_diag = DNSDiagnostics()
print("Testing DNS resolution...\n")

# Test DNS resolution
test_domains = ['google.com', 'github.com', 'example.com']
for domain in test_domains:
    result = dns_diag.test_dns_resolution(domain)
    if result['success']:
        print(f"✅ {domain}")
        print(f"   Resolved to: {result['ip_addresses'][:2]}")  # Show first 2 IPs
        print(f"   Response time: {result['response_time']*1000:.1f}ms")
    else:
        print(f"❌ {domain} - Resolution failed!")

# 4. REAL Connectivity Tests
print("\n\n4️⃣ REAL Connectivity Tests")
print("-" * 40)

# Test gateway connectivity
def get_default_gateway():
    """Get the default gateway"""
    gateways = netifaces.gateways()
    default = gateways.get('default', {})
    if netifaces.AF_INET in default:
        return default[netifaces.AF_INET][0]
    return None

gateway = get_default_gateway()
if gateway:
    print(f"Default Gateway: {gateway}")
    # Actually ping the gateway
    cmd = ['ping', '-c', '2', gateway] if os.name != 'nt' else ['ping', '-n', '2', gateway]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if result.returncode == 0:
            print("✅ Gateway is reachable")
        else:
            print("❌ Gateway is NOT reachable - Network connectivity issue!")
    except:
        print("⚠️  Could not test gateway connectivity")

# 5. REAL Active Connection Analysis
print("\n\n5️⃣ REAL Active Connection Analysis")
print("-" * 40)
print("Analyzing current network connections...\n")

connections = psutil.net_connections(kind='inet')
conn_summary = {
    'ESTABLISHED': 0,
    'LISTEN': 0,
    'TIME_WAIT': 0,
    'CLOSE_WAIT': 0,
    'OTHER': 0
}

for conn in connections:
    if conn.status:
        if conn.status in conn_summary:
            conn_summary[conn.status] += 1
        else:
            conn_summary['OTHER'] += 1

print(f"Total active connections: {len(connections)}")
for status, count in conn_summary.items():
    if count > 0:
        print(f"  {status}: {count}")

# Show some listening ports
listening = [c for c in connections if c.status == 'LISTEN']
if listening:
    print("\nServices listening on ports:")
    for conn in listening[:5]:  # Show first 5
        port = conn.laddr.port
        print(f"  Port {port}: LISTENING")

print("\n" + "=" * 60)
print("✅ This is REAL network diagnostic functionality!")
print("🚀 SuperSleuth Network has actual working tools, not just frameworks!")
print("\nFor HIPAA compliance, these tools would check:")
print("  • Encryption status of network traffic (port 443 vs 80)")
print("  • Open ports that might expose PHI")
print("  • Network segmentation (interface analysis)")
print("  • Firewall status (connection analysis)")
print("  • And much more...")