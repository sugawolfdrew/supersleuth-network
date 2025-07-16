#!/usr/bin/env python3
"""
DNS Diagnostics Demo - How Claude Code uses DNS diagnostic tools

This demonstrates how Claude Code would use the DNS diagnostics module
to help IT professionals troubleshoot DNS-related issues.
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.diagnostics.dns_diagnostics import (
    resolve_hostname,
    test_dns_server,
    get_system_dns_servers,
    diagnose_dns_issue,
    analyze_dns_performance,
    test_dns_resolution_batch
)


def scenario_1_cant_access_website():
    """IT Professional: 'I can't access github.com'"""
    
    print("\n🔍 SCENARIO 1: Can't Access Specific Website")
    print("=" * 50)
    print("IT Professional: 'I can't access github.com'\n")
    
    print("Claude Code: Let me diagnose the DNS resolution for github.com...\n")
    
    # First, test if we can resolve the domain
    result = resolve_hostname('github.com')
    
    if result['resolved']:
        print(f"✅ DNS resolution successful!")
        print(f"   - Resolved to: {', '.join(result['ip_addresses'])}")
        print(f"   - Resolution time: {result['resolution_time']}ms")
        print("\nClaude Code: DNS is working. The issue might be:")
        print("   • Firewall blocking the connection")
        print("   • The website might be down")
        print("   • Network routing issues")
        print("   Let me create a connectivity test to the resolved IP...")
    else:
        print(f"❌ DNS resolution failed: {result.get('error', 'Unknown error')}")
        print("\nClaude Code: This is a DNS issue. Let me check your DNS servers...")
        
        # Check DNS configuration
        dns_config = get_system_dns_servers()
        print(f"\n   Your DNS servers: {dns_config.get('all_dns', ['None found'])}")
        
        # Test if DNS servers are reachable
        for dns in dns_config.get('all_dns', [])[:1]:  # Test first DNS
            server_test = test_dns_server(dns)
            if not server_test['reachable']:
                print(f"   ❌ DNS server {dns} is not responding")
                print("\n   Recommendation: Try using Google DNS (8.8.8.8)")


def scenario_2_internet_slow():
    """IT Professional: 'Internet is really slow today'"""
    
    print("\n\n🔍 SCENARIO 2: Slow Internet")
    print("=" * 50)
    print("IT Professional: 'Internet is really slow today'\n")
    
    print("Claude Code: Let me check if DNS performance might be contributing...\n")
    
    # Test DNS resolution speed for multiple domains
    test_domains = ['google.com', 'amazon.com', 'microsoft.com', 'apple.com']
    results = test_dns_resolution_batch(test_domains)
    
    # Analyze performance
    analysis = analyze_dns_performance(results)
    
    print(f"📊 DNS Performance Analysis:")
    print(f"   Average resolution time: {analysis['statistics'].get('avg_resolution_time', 'N/A')}ms")
    
    if analysis['statistics'].get('avg_resolution_time', 0) > 100:
        print("   ⚠️  DNS is slow! This is contributing to your internet slowness.")
        
        # Compare with public DNS
        print("\n   Testing public DNS servers for comparison...")
        google_dns = test_dns_server('8.8.8.8', 'google.com')
        cloudflare_dns = test_dns_server('1.1.1.1', 'google.com')
        
        print(f"\n   Your DNS vs Public DNS:")
        print(f"   Current DNS: {analysis['statistics']['avg_resolution_time']}ms average")
        if google_dns['reachable']:
            print(f"   Google DNS (8.8.8.8): {google_dns['response_time']}ms")
        if cloudflare_dns['reachable']:
            print(f"   Cloudflare DNS (1.1.1.1): {cloudflare_dns['response_time']}ms")
            
        print("\n   Claude Code: Switching to a faster DNS server could help!")
    else:
        print("   ✅ DNS performance is good.")
        print("\n   Claude Code: DNS is not the bottleneck. Let me check bandwidth...")


def scenario_3_intermittent_issues():
    """IT Professional: 'Some websites work, others don't'"""
    
    print("\n\n🔍 SCENARIO 3: Intermittent Website Access")
    print("=" * 50)
    print("IT Professional: 'Some websites work, others don't'\n")
    
    print("Claude Code: This sounds like a selective DNS issue. Let me investigate...\n")
    
    # Use the diagnose function
    diagnosis = diagnose_dns_issue("some websites fail to resolve")
    
    # Test a mix of domains
    test_domains = [
        'google.com',      # Usually works
        'github.com',      # Developer site
        'facebook.com',    # Social media (might be blocked)
        'adult-site.com',  # Often blocked by DNS filters
        'malware-test.com' # Security test
    ]
    
    print("Testing various domain categories...")
    results = test_dns_resolution_batch(test_domains)
    
    working = []
    failing = []
    
    for domain, result in results.items():
        if result['resolved']:
            working.append(domain)
        else:
            failing.append(domain)
    
    if failing and working:
        print(f"\n✅ Working: {', '.join(working)}")
        print(f"❌ Failing: {', '.join(failing)}")
        
        print("\nClaude Code: This pattern suggests:")
        print("   • DNS filtering/blocking is active")
        print("   • Might be using OpenDNS or similar filtered service")
        print("   • Corporate firewall with DNS filtering")
        print("\nTry using 8.8.8.8 to bypass filtering (if allowed by policy)")


def scenario_4_dns_hijacking_check():
    """IT Professional: 'I think my DNS might be compromised'"""
    
    print("\n\n🔍 SCENARIO 4: DNS Security Check")
    print("=" * 50)
    print("IT Professional: 'I think my DNS might be compromised'\n")
    
    print("Claude Code: Let me run a DNS security check...\n")
    
    # Get current DNS servers
    dns_config = get_system_dns_servers()
    print(f"Current DNS servers: {dns_config.get('all_dns', ['None found'])}")
    
    # Test known good domains and check if IPs match expected
    security_test_domains = {
        'google.com': ['142.250', '172.217', '142.251'],  # Google IP prefixes
        'cloudflare.com': ['104.16', '104.17', '104.18'],  # Cloudflare prefixes
    }
    
    suspicious = False
    
    for domain, expected_prefixes in security_test_domains.items():
        result = resolve_hostname(domain)
        if result['resolved'] and result['ip_addresses']:
            ip = result['ip_addresses'][0]
            if not any(ip.startswith(prefix) for prefix in expected_prefixes):
                print(f"⚠️  WARNING: {domain} resolved to unexpected IP: {ip}")
                suspicious = True
            else:
                print(f"✅ {domain} resolved correctly: {ip}")
    
    if suspicious:
        print("\n🚨 POTENTIAL DNS HIJACKING DETECTED!")
        print("   Recommendations:")
        print("   • Switch to trusted DNS servers (8.8.8.8 or 1.1.1.1)")
        print("   • Check for malware on your system")
        print("   • Verify router DNS settings haven't been changed")
    else:
        print("\n✅ DNS responses appear legitimate")


if __name__ == "__main__":
    print("🌐 DNS DIAGNOSTICS TOOLKIT DEMO")
    print("Demonstrating how Claude Code uses DNS diagnostic tools")
    
    # Run scenarios
    scenario_1_cant_access_website()
    scenario_2_internet_slow()
    scenario_3_intermittent_issues()
    scenario_4_dns_hijacking_check()
    
    print("\n\n✨ These DNS diagnostic tools help Claude Code quickly identify")
    print("   and resolve the most common network connectivity issues!")