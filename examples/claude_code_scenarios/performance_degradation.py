#!/usr/bin/env python3
"""
Claude Code Scenario: Complex Performance Degradation

This script demonstrates how Claude Code handles natural language requests
for complex, multi-faceted performance issues that require deep analysis.
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.claude_code_integration import ClaudeCodeIntegration


class PerformanceDegradationScenarios:
    """Collection of complex performance degradation scenarios"""
    
    def __init__(self):
        self.claude = ClaudeCodeIntegration()
    
    async def scenario_database_performance(self):
        """Scenario 1: Database performance degradation"""
        print("="*80)
        print("SCENARIO 1: Database Performance Crisis")
        print("="*80)
        
        request = """
        Database queries that normally take 100ms are now taking 5-10 seconds.
        Affects all applications using main database cluster (10.2.10.1-3).
        Started gradually last week, now critical. Customer transactions timing out.
        Database team says servers look fine. Network team says network is fine.
        Nobody knows what's wrong!
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("🔍 Initiating cross-team diagnostic coordination...\n")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("MULTI-LAYER DIAGNOSTIC APPROACH:")
        print("-"*40)
        
        print("\n1. Database Layer Analysis:")
        print("   - Query response times: 5000-10000ms (baseline: 100ms)")
        print("   - Connection pool: 95% utilized")
        print("   - CPU/Memory on DB servers: Normal (30% / 45%)")
        
        print("\n2. Network Layer Investigation:")
        print("   - RoutingDiagnostics: Latency to DB cluster normal (2ms)")
        print("   - NetworkMetrics: No packet loss detected")
        print("   - AdvancedDiagnostics: TCP analysis shows issues...")
        
        print("\n3. Deep TCP Analysis Results:")
        print("   - TCP Retransmissions: 15% (normal: <1%)")
        print("   - Zero Window events: 847/hour")
        print("   - Window scaling problems detected")
        print("   - MTU mismatches causing fragmentation")
        
        print("\n4. Root Cause Identified:")
        print("   - Jumbo frames enabled on DB servers (9000 bytes)")
        print("   - Core switches only support 1500 MTU")
        print("   - TCP performance severely degraded")
        
        print("\n" + "-"*40)
        print("PERFORMANCE ANALYSIS REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_application_stack(self):
        """Scenario 2: Full application stack degradation"""
        print("\n\n" + "="*80)
        print("SCENARIO 2: Multi-Tier Application Degradation")
        print("="*80)
        
        request = """
        Our e-commerce platform is falling apart. Frontend load balancer 
        shows healthy, but users report:
        - Page loads take 30+ seconds
        - Shopping cart randomly empties  
        - API calls timeout 50% of the time
        - Worse during peak hours (10 AM - 2 PM)
        Affects web tier (10.1.10.0/24), app tier (10.1.20.0/24), 
        and database tier (10.1.30.0/24).
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("FULL STACK ANALYSIS WORKFLOW:")
        print("-"*40)
        
        print("\n1. Load Balancer & Web Tier:")
        print("   - HTTPDiagnostics: Testing all web servers")
        print("   - Response times: Vary wildly (1s - 45s)")
        print("   - Session persistence failing")
        
        print("\n2. Application Tier Analysis:")
        print("   - PerformanceAnalyzer: Memory pressure detected")
        print("   - GC pauses: Up to 8 seconds")
        print("   - Connection pool exhaustion")
        
        print("\n3. Database Tier Investigation:")
        print("   - Slow query log: 2000+ slow queries/hour")
        print("   - Lock contention on inventory table")
        print("   - Replication lag: 5+ minutes")
        
        print("\n4. Network Infrastructure:")
        print("   - TopologyInterference: Found network loops!")
        print("   - STP reconvergence during peak hours")
        print("   - Causing intermittent connectivity")
        
        print("\n5. Correlation Analysis:")
        print("   - Peak hours → More traffic → STP flapping")
        print("   - Network instability → Connection drops")
        print("   - Dropped connections → App tier retry storms")
        print("   - Retry storms → Database overload")
        
        print("\n" + "-"*40)
        print("STACK ANALYSIS REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_wan_optimization(self):
        """Scenario 3: WAN performance degradation"""
        print("\n\n" + "="*80)
        print("SCENARIO 3: WAN Link Performance Degradation")
        print("="*80)
        
        request = """
        All remote offices complaining about slow access to HQ resources.
        File transfers that took 5 minutes now take 45 minutes.
        Video conferences pixelated and dropping. VoIP calls have echo.
        WAN links show only 60% utilization. ISP says circuits are clean.
        Affecting London, Tokyo, Sydney offices connecting to NYC HQ.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("WAN PERFORMANCE DEEP DIVE:")
        print("-"*40)
        
        print("\n1. Circuit Utilization Analysis:")
        print("   - Bandwidth usage: 60% average")
        print("   - But microbursts hitting 100% for 50-100ms")
        print("   - Causing tail drops and retransmissions")
        
        print("\n2. QoS Policy Inspection:")
        print("   - Voice traffic: Not properly marked (DSCP 0)")
        print("   - Video: Competing with bulk data")
        print("   - Business apps: In default queue")
        
        print("\n3. WAN Optimization Devices:")
        print("   - Cache hit ratio: Dropped from 70% to 15%")
        print("   - Compression disabled after firmware update")
        print("   - TCP optimization not working")
        
        print("\n4. Latency & Jitter Analysis:")
        print("   - Base latency: Normal (London: 80ms, Tokyo: 120ms)")
        print("   - Jitter: Excessive (40-60ms) - killing real-time apps")
        print("   - Packet reordering: 5% of packets")
        
        print("\n5. Multi-Path Issues:")
        print("   - SDWAN using multiple ISPs")
        print("   - Load balancing per-packet (should be per-flow)")
        print("   - Causing out-of-order delivery")
        
        print("\n" + "-"*40)
        print("WAN OPTIMIZATION REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_virtualization_impact(self):
        """Scenario 4: Virtualization infrastructure impact"""
        print("\n\n" + "="*80)
        print("SCENARIO 4: Virtualization Performance Impact")
        print("="*80)
        
        request = """
        Random VMs experiencing severe performance issues. No pattern to
        which VMs are affected. Sometimes VM1 is slow, then fine, then VM5
        is slow. Happens across different hosts and datastores.
        vCenter shows resources available. Network team sees no issues.
        VMware team insists infrastructure is healthy. Users are angry.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("VIRTUALIZATION LAYER ANALYSIS:")
        print("-"*40)
        
        print("\n1. VM Network Performance Testing:")
        print("   - Inter-VM latency: Spikes to 100ms (normal: <1ms)")
        print("   - Packet loss between VMs: 2-5%")
        print("   - Affecting VMs on same host!")
        
        print("\n2. Virtual Switch Investigation:")
        print("   - NetworkMetrics: vSwitch CPU hitting 100%")
        print("   - Dropped packets at virtual layer")
        print("   - SR-IOV not enabled for high-traffic VMs")
        
        print("\n3. Physical Network Correlation:")
        print("   - TopologyInterference: Found the pattern!")
        print("   - VMs slow when on hosts using NIC team 1")
        print("   - NIC firmware bug causing interrupts storm")
        
        print("\n4. Storage Network Impact:")
        print("   - iSCSI traffic sharing same NICs")
        print("   - No proper VLAN separation")
        print("   - Storage latency affecting VM performance")
        
        print("\n5. vMotion Storms:")
        print("   - DRS aggressively moving VMs")
        print("   - vMotion traffic saturating 10G links")
        print("   - Causing the 'random' performance issues")
        
        print("\n" + "-"*40)
        print("VIRTUALIZATION ANALYSIS REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_cloud_hybrid(self):
        """Scenario 5: Hybrid cloud performance issues"""
        print("\n\n" + "="*80)
        print("SCENARIO 5: Hybrid Cloud Performance Degradation")
        print("="*80)
        
        request = """
        After migrating half our apps to AWS, performance is terrible.
        On-premise apps calling cloud APIs timeout frequently.
        Cloud apps accessing on-prem database are extremely slow.
        Direct Connect link shows only 30% utilization.
        Worse: same app works fine when all components are in same location.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("HYBRID CLOUD ANALYSIS:")
        print("-"*40)
        
        print("\n1. Direct Connect Analysis:")
        print("   - Bandwidth: 30% utilized (3Gbps of 10Gbps)")
        print("   - Latency: 25ms (expected for distance)")
        print("   - But... BGP flapping every few minutes!")
        
        print("\n2. Application Architecture Issues:")
        print("   - Chatty protocols: 100+ API calls per transaction")
        print("   - Each call = 25ms latency minimum")
        print("   - Total latency: 2.5 seconds just in transit!")
        
        print("\n3. DNS Split-Brain Problems:")
        print("   - DNSDiagnostics: Cloud apps resolving to public IPs")
        print("   - Should use Direct Connect private IPs")
        print("   - Adding 50ms+ per connection")
        
        print("\n4. Security Layer Impact:")
        print("   - Cloud WAF inspecting internal traffic")
        print("   - On-prem firewall doing deep inspection")
        print("   - Double inspection adding 200ms")
        
        print("\n5. Bandwidth Asymmetry:")
        print("   - Uploads to cloud: Fast (10Gbps)")
        print("   - Downloads from cloud: Throttled (1Gbps)")
        print("   - Backup traffic consuming download")
        
        print("\n" + "-"*40)
        print("HYBRID CLOUD REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_everything_slow(self):
        """Scenario 6: Everything is slow - complex root cause"""
        print("\n\n" + "="*80)
        print("SCENARIO 6: 'Everything Is Slow' - The Ultimate Challenge")
        print("="*80)
        
        request = """
        HELP! Everything is slow. Email, internet, applications, file shares,
        printing, even phone calls. Started Monday morning. Gets worse 
        throughout the day. By 4 PM, network is almost unusable.
        Affects all 5 buildings on campus. 2000+ users impacted.
        We've rebooted everything. Nothing helps. Business is at standstill.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        print("🚨 CRITICAL: Enterprise-wide performance crisis detected\n")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("COMPREHENSIVE DIAGNOSTIC EXECUTION:")
        print("-"*40)
        
        print("\n1. Initial Assessment (5 minutes):")
        print("   ✓ All services affected = Common infrastructure")
        print("   ✓ Progressive degradation = Resource exhaustion")
        print("   ✓ Time-based pattern = Accumulation issue")
        
        print("\n2. Infrastructure Discovery:")
        print("   - TopologyInterference: Mapping entire network")
        print("   - Found: All buildings connect through core switch pair")
        print("   - Critical: Spanning Tree root bridge identified")
        
        print("\n3. Progressive Degradation Analysis:")
        print("   - 9 AM: Network normal")
        print("   - 12 PM: 20% performance loss")
        print("   - 4 PM: 80% performance loss")
        print("   - Pattern: Exponential decay!")
        
        print("\n4. Deep Dive Findings:")
        print("   - NetworkMetrics: Broadcast storms detected!")
        print("   - Rate: 50K broadcasts/sec by 4 PM")
        print("   - Source: Core switch MAC table full")
        print("   - Cause: MAC learning disabled on uplinks")
        
        print("\n5. Cascading Failure Analysis:")
        print("   - Full MAC table → Unknown unicast flooding")
        print("   - Flooding → CPU high on all switches")
        print("   - High CPU → Slow STP processing")
        print("   - Slow STP → More flooding")
        print("   - Feedback loop of death!")
        
        print("\n6. Why Monday Morning?")
        print("   - Weekend maintenance disabled MAC aging")
        print("   - Monday traffic fills tables")
        print("   - By afternoon, tables overflow")
        print("   - Each day would start fresh (reboot)")
        
        print("\n" + "-"*40)
        print("ROOT CAUSE ANALYSIS REPORT:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    def demonstrate_diagnostic_patterns(self):
        """Show Claude's diagnostic patterns for performance issues"""
        print("\n\n" + "="*80)
        print("PERFORMANCE DIAGNOSTIC PATTERNS")
        print("="*80)
        
        print("\nClaude Code uses these patterns to diagnose performance issues:\n")
        
        patterns = {
            "Gradual Degradation": {
                "symptoms": ["Slowly getting worse", "Progressive slowdown"],
                "approach": "Look for resource exhaustion, growth issues",
                "tools": ["NetworkMetrics trends", "Capacity analysis"]
            },
            "Time-Based Issues": {
                "symptoms": ["Specific times", "Business hours", "Patterns"],
                "approach": "Correlate with scheduled events, load patterns",
                "tools": ["Historical analysis", "Traffic patterns"]
            },
            "Sudden Degradation": {
                "symptoms": ["Was fine, now broken", "Sudden slowness"],
                "approach": "Look for recent changes, failures",
                "tools": ["Change tracking", "Failure detection"]
            },
            "Intermittent Issues": {
                "symptoms": ["Sometimes slow", "Random", "Unpredictable"],
                "approach": "Long-term monitoring, pattern detection",
                "tools": ["Continuous monitoring", "Statistical analysis"]
            },
            "Location-Specific": {
                "symptoms": ["Only in certain areas", "Site-specific"],
                "approach": "Compare locations, find differences",
                "tools": ["Comparative analysis", "Path tracing"]
            },
            "Service-Specific": {
                "symptoms": ["Only certain apps", "Specific protocols"],
                "approach": "Protocol analysis, service dependencies",
                "tools": ["Protocol analyzers", "Dependency mapping"]
            }
        }
        
        for pattern_name, details in patterns.items():
            print(f"{pattern_name}:")
            print(f"  Symptoms: {', '.join(details['symptoms'])}")
            print(f"  Approach: {details['approach']}")
            print(f"  Primary tools: {', '.join(details['tools'])}")
            print()


async def performance_assistant():
    """Interactive performance troubleshooting assistant"""
    claude = ClaudeCodeIntegration()
    
    print("\n" + "="*80)
    print("PERFORMANCE TROUBLESHOOTING ASSISTANT")
    print("="*80)
    
    print("\nI'll help you diagnose performance issues. Let me ask a few questions:\n")
    
    # Gather symptoms
    print("1. What's running slowly?")
    print("   a) Specific application")
    print("   b) Internet access")
    print("   c) Internal services")
    print("   d) Everything")
    what = input("   Select (a-d): ").strip().lower()
    
    print("\n2. When did it start?")
    print("   a) Just now / Today")
    print("   b) Few days ago")
    print("   c) Gradually over time")
    print("   d) After a change")
    when = input("   Select (a-d): ").strip().lower()
    
    print("\n3. Who is affected?")
    print("   a) Just me")
    print("   b) My department")
    print("   c) Specific location")
    print("   d) Everyone")
    who = input("   Select (a-d): ").strip().lower()
    
    print("\n4. Any patterns?")
    print("   a) Constant slowness")
    print("   b) Specific times")
    print("   c) Getting worse")
    print("   d) Random/intermittent")
    pattern = input("   Select (a-d): ").strip().lower()
    
    # Build diagnosis request
    what_map = {
        'a': "specific application",
        'b': "internet access", 
        'c': "internal services",
        'd': "everything on the network"
    }
    
    when_map = {
        'a': "started today",
        'b': "started a few days ago",
        'c': "has been gradually getting worse",
        'd': "started after recent changes"
    }
    
    who_map = {
        'a': "affecting just my computer",
        'b': "affecting my entire department",
        'c': "affecting specific location",
        'd': "affecting all users"
    }
    
    pattern_map = {
        'a': "Performance is constantly slow",
        'b': "Slowness occurs at specific times",
        'c': "Performance is progressively degrading",
        'd': "Issues are random and intermittent"
    }
    
    specific_app = ""
    if what == 'a':
        specific_app = input("\n   Which application? ").strip()
    
    request = f"""
    Performance issue: {what_map.get(what, 'unspecified')} is very slow.
    {specific_app if specific_app else ''}
    This {when_map.get(when, 'recently started')} and is 
    {who_map.get(who, 'affecting users')}.
    {pattern_map.get(pattern, 'No clear pattern identified')}.
    Need comprehensive performance diagnosis and recommendations.
    """
    
    print("\n" + "-"*40)
    print("Analyzing your performance issue...")
    print("-"*40)
    
    results = await claude.diagnose(request)
    
    print("\n" + "="*40)
    print("PERFORMANCE DIAGNOSIS:")
    print("="*40)
    print(results['report'])
    
    print("\n" + "-"*40)
    print("IMMEDIATE ACTIONS:")
    print("-"*40)
    print("1. Save this diagnostic report")
    print("2. Try the top recommendation first")
    print("3. Monitor for improvement")
    print("4. Escalate if no progress in 30 minutes")


async def main():
    """Run all performance degradation scenarios"""
    scenarios = PerformanceDegradationScenarios()
    
    # Run each scenario
    await scenarios.scenario_database_performance()
    await scenarios.scenario_application_stack()
    await scenarios.scenario_wan_optimization()
    await scenarios.scenario_virtualization_impact()
    await scenarios.scenario_cloud_hybrid()
    await scenarios.scenario_everything_slow()
    
    # Demonstrate patterns
    scenarios.demonstrate_diagnostic_patterns()
    
    # Offer performance assistant
    print("\n\nWould you like to try the performance troubleshooting assistant? (y/n): ", end="")
    if input().lower() == 'y':
        await performance_assistant()
    
    print("\n✓ Performance degradation scenarios completed!")
    print("\nKey Takeaway: Complex performance issues often have multiple contributing")
    print("factors. Claude Code's systematic approach helps identify all layers of")
    print("problems, from obvious bottlenecks to subtle cascading failures.")


if __name__ == "__main__":
    asyncio.run(main())