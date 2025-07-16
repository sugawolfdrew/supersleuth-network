#!/usr/bin/env python3
"""
Claude Code Scenario: Diagnosing Slow Network Performance

This script demonstrates how Claude Code handles natural language requests
for network performance issues, showing the diagnostic workflow and results.
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.claude_code_integration import ClaudeCodeIntegration


class SlowNetworkScenarios:
    """Collection of slow network diagnostic scenarios"""
    
    def __init__(self):
        self.claude = ClaudeCodeIntegration()
    
    async def scenario_general_slowness(self):
        """Scenario 1: General network slowness complaint"""
        print("="*80)
        print("SCENARIO 1: General Network Slowness")
        print("="*80)
        
        request = """
        Users are complaining that 'everything is slow' on the network. 
        Started this morning around 9 AM. Affecting all departments 
        but especially bad in the accounting department (subnet 192.168.50.0/24).
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        # Show what Claude Code identified
        context = results['context']
        print(f"Intent Identified: {context['intent']}")
        print(f"Affected Users: {context['affected_users']}")
        print(f"Timeline: {context['timeline']}")
        print(f"Priority: {context['priority']}")
        
        print("\nTools Orchestrated:")
        print("1. NetworkMetrics - Collecting baseline performance data")
        print("2. PerformanceAnalyzer - Analyzing subnet 192.168.50.0/24")
        print("3. RoutingDiagnostics - Checking routing paths")
        print("4. TopologyInterference - Identifying network bottlenecks")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_specific_application(self):
        """Scenario 2: Specific application performance issue"""
        print("\n\n" + "="*80)
        print("SCENARIO 2: Application-Specific Performance")
        print("="*80)
        
        request = """
        Our CRM system at https://crm.company.local is extremely slow. 
        Page loads take 30+ seconds. Database queries timeout frequently.
        Only affecting users accessing from remote VPN connections.
        The issue is critical as sales team can't process orders.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. HTTPDiagnostics - Testing CRM response times")
        print("2. DNSDiagnostics - Checking DNS resolution for CRM")
        print("3. RoutingDiagnostics - Comparing VPN vs local routes")
        print("4. PortScanner - Verifying database connectivity")
        print("5. PerformanceAnalyzer - Measuring VPN tunnel performance")
        
        print("\nDiagnostic Approach:")
        print("- Compare performance: VPN users vs local users")
        print("- Test each component: Web server, Database, DNS")
        print("- Analyze VPN tunnel characteristics")
        print("- Check for MTU issues with VPN")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_time_based_pattern(self):
        """Scenario 3: Time-based performance pattern"""
        print("\n\n" + "="*80)
        print("SCENARIO 3: Time-Based Performance Pattern")
        print("="*80)
        
        request = """
        Network performance degrades every day between 2 PM and 4 PM.
        Internet browsing becomes sluggish, file transfers slow to a crawl.
        Internal services seem unaffected. Been happening for the past week.
        Need to identify the cause without disrupting business operations.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. NetworkMetrics - Historical analysis for 2-4 PM window")
        print("2. PerformanceAnalyzer - Bandwidth utilization patterns")
        print("3. AdvancedDiagnostics - Traffic classification analysis")
        print("4. RoutingDiagnostics - Internet vs internal path comparison")
        
        print("\nPattern Analysis:")
        print("- Correlating network metrics with time window")
        print("- Identifying top bandwidth consumers")
        print("- Checking for scheduled tasks/backups")
        print("- Analyzing QoS policies")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_geographic_performance(self):
        """Scenario 4: Geographic/location-based performance issue"""
        print("\n\n" + "="*80)
        print("SCENARIO 4: Geographic Performance Differences")
        print("="*80)
        
        request = """
        Branch offices in Chicago and Dallas experiencing slow access to 
        headquarters resources in New York. File shares on 10.1.50.10 
        taking minutes to open. Same files open instantly from NY office.
        Remote desktop sessions frequently disconnect. Started after 
        network upgrade last Tuesday.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. RoutingDiagnostics - Trace routes from each location")
        print("2. PerformanceAnalyzer - Latency and bandwidth tests")
        print("3. AdvancedDiagnostics - MTU path discovery")
        print("4. NetworkMetrics - WAN link utilization")
        
        print("\nMulti-Site Analysis:")
        print("- Chicago → NY: Full path analysis")
        print("- Dallas → NY: Full path analysis")
        print("- NY Local: Baseline comparison")
        print("- Identifying divergence points")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    async def scenario_gradual_degradation(self):
        """Scenario 5: Gradual performance degradation"""
        print("\n\n" + "="*80)
        print("SCENARIO 5: Gradual Performance Degradation")
        print("="*80)
        
        request = """
        Network performance has been gradually getting worse over the 
        past month. Initially barely noticeable, now significantly impacting 
        productivity. Affects all services - email, web, file transfers.
        No specific pattern identified. Network team hasn't made any changes.
        """
        
        print(f"\nUser Request: {request.strip()}")
        print("\nClaude Code is analyzing the request and orchestrating diagnostics...")
        
        results = await self.claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC WORKFLOW EXECUTED:")
        print("-"*40)
        
        print("\nTools Orchestrated:")
        print("1. NetworkMetrics - Long-term trend analysis")
        print("2. TopologyInterference - Network growth assessment")
        print("3. PerformanceAnalyzer - Capacity planning metrics")
        print("4. AdvancedDiagnostics - Error rate analysis")
        
        print("\nTrend Analysis Approach:")
        print("- Baseline vs current performance metrics")
        print("- Network growth: devices, traffic volume")
        print("- Infrastructure aging: error rates, retransmissions")
        print("- Capacity thresholds and tipping points")
        
        print("\n" + "-"*40)
        print("FINDINGS:")
        print("-"*40)
        print(results['report'])
        
        return results
    
    def demonstrate_natural_language_variations(self):
        """Show how different phrasings lead to similar diagnostic approaches"""
        print("\n\n" + "="*80)
        print("NATURAL LANGUAGE UNDERSTANDING DEMONSTRATION")
        print("="*80)
        
        variations = [
            "Network is slow",
            "Internet is really sluggish today",
            "Everything takes forever to load",
            "Experiencing significant latency issues accessing cloud resources",
            "The network is garbage right now - fix it!",
            "Performance degradation observed across multiple network segments"
        ]
        
        print("\nDifferent ways users might describe the same problem:")
        
        for i, request in enumerate(variations, 1):
            context = self.claude.analyze_request(request)
            print(f"\n{i}. User says: \"{request}\"")
            print(f"   Claude identifies: Intent={context.intent.value}, "
                  f"Priority={context.priority}")
        
        print("\nKey Insight: Claude Code understands context and intent regardless")
        print("of technical expertise or emotional state of the user.")


async def interactive_mode():
    """Run in interactive mode for custom scenarios"""
    claude = ClaudeCodeIntegration()
    
    print("\n" + "="*80)
    print("INTERACTIVE MODE: Slow Network Diagnostics")
    print("="*80)
    print("\nDescribe your network performance issue in natural language.")
    print("Example: 'The network is slow when accessing cloud services'")
    print("\nType 'exit' to quit.\n")
    
    while True:
        request = input("Your request: ").strip()
        
        if request.lower() == 'exit':
            break
        
        if not request:
            continue
        
        print("\nProcessing your request...")
        results = await claude.diagnose(request)
        
        print("\n" + "-"*40)
        print("DIAGNOSTIC RESULTS:")
        print("-"*40)
        print(results['report'])
        print("\n")


async def main():
    """Run all slow network scenarios"""
    scenarios = SlowNetworkScenarios()
    
    # Run each scenario
    await scenarios.scenario_general_slowness()
    await scenarios.scenario_specific_application()
    await scenarios.scenario_time_based_pattern()
    await scenarios.scenario_geographic_performance()
    await scenarios.scenario_gradual_degradation()
    
    # Demonstrate natural language understanding
    scenarios.demonstrate_natural_language_variations()
    
    # Offer interactive mode
    print("\n\nWould you like to try interactive mode? (y/n): ", end="")
    if input().lower() == 'y':
        await interactive_mode()
    
    print("\n✓ Slow network diagnostic scenarios completed!")


if __name__ == "__main__":
    asyncio.run(main())