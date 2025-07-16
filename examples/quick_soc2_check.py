#!/usr/bin/env python3
"""
Quick SOC2 Compliance Check Example

This demonstrates how Claude Code would handle a natural language request like:
"Check to see if my network is SOC2 compliant"
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.compliance import assess_soc2_compliance, TrustServicePrinciple


def natural_language_soc2_check():
    """
    Simulate how Claude Code would handle: "Check to see if my network is SOC2 compliant"
    """
    print("🤖 Claude Code: I'll check your network's SOC2 compliance status.\n")
    
    # In a real scenario, Claude Code would gather this information
    # from the network environment or ask the IT professional
    print("First, let me gather some information about your organization...\n")
    
    # Simulated environment assessment
    network_scope = {
        'organization_name': 'Example Corp',
        'system_name': 'Production Network Infrastructure',
        'audit_period': {
            'start': '2024-01-01',
            'end': '2024-12-31'
        },
        # These would be determined by actual network analysis
        'has_code_of_conduct': True,
        'ethics_training_implemented': True,
        'board_security_oversight': True
    }
    
    print("📋 Running SOC2 compliance assessment...")
    print("   - Checking Security principle (mandatory)")
    print("   - Checking Availability principle")
    print("   - Checking Confidentiality principle")
    print()
    
    # Run the assessment with multiple principles
    results = assess_soc2_compliance(
        network_scope,
        principles=['AVAILABILITY', 'CONFIDENTIALITY']
    )
    
    # Present results in a user-friendly way
    print("=" * 60)
    print("📊 SOC2 COMPLIANCE ASSESSMENT RESULTS")
    print("=" * 60)
    print()
    
    compliance_score = results['summary']['compliance_percentage']
    risk_level = results['summary'].get('risk_level', 'UNKNOWN')
    
    # Overall status
    if compliance_score >= 95:
        status_emoji = "✅"
        status_text = "EXCELLENT - Your network appears to be SOC2 compliant!"
    elif compliance_score >= 80:
        status_emoji = "⚠️"
        status_text = "GOOD - Minor improvements needed for full compliance"
    elif compliance_score >= 60:
        status_emoji = "⚠️"
        status_text = "FAIR - Several areas need attention"
    else:
        status_emoji = "❌"
        status_text = "NEEDS WORK - Significant compliance gaps identified"
    
    print(f"{status_emoji} Overall Status: {status_text}")
    print(f"📈 Compliance Score: {compliance_score}%")
    print(f"⚡ Risk Level: {risk_level}")
    print()
    
    # Breakdown by principle
    print("Trust Service Principles Assessment:")
    print("-" * 40)
    
    # Count controls by principle and status
    principle_summary = {}
    for control in results['controls']:
        principle = control['category']
        if principle not in principle_summary:
            principle_summary[principle] = {
                'compliant': 0,
                'partial': 0,
                'non_compliant': 0,
                'total': 0
            }
        principle_summary[principle][control['status']] += 1
        principle_summary[principle]['total'] += 1
    
    for principle, counts in principle_summary.items():
        compliance_rate = (counts['compliant'] / counts['total'] * 100) if counts['total'] > 0 else 0
        print(f"\n{principle}:")
        print(f"  Compliance Rate: {compliance_rate:.0f}%")
        print(f"  ✓ Compliant: {counts['compliant']}/{counts['total']}")
        if counts['partial'] > 0:
            print(f"  ⚠ Partial: {counts['partial']}")
        if counts['non_compliant'] > 0:
            print(f"  ✗ Non-Compliant: {counts['non_compliant']}")
    
    # Critical findings
    critical_findings = results['summary'].get('critical_findings', [])
    if critical_findings:
        print("\n🚨 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:")
        print("-" * 40)
        for i, finding in enumerate(critical_findings[:5], 1):
            print(f"{i}. {finding}")
    
    # Quick wins
    quick_wins = results['summary'].get('quick_wins', [])
    if quick_wins:
        print("\n💡 QUICK WINS (Easy fixes to improve compliance):")
        print("-" * 40)
        for i, win in enumerate(quick_wins[:3], 1):
            print(f"{i}. {win}")
    
    # Recommendations
    print("\n📋 RECOMMENDATIONS:")
    print("-" * 40)
    
    if compliance_score < 80:
        print("1. Address all critical and high-severity findings immediately")
        print("2. Implement missing security controls identified in the assessment")
        print("3. Schedule a follow-up assessment after remediation")
    else:
        print("1. Continue monitoring and maintaining current controls")
        print("2. Address any partial compliance items")
        print("3. Schedule regular quarterly assessments")
    
    print("\n🔧 NEXT STEPS:")
    print("-" * 40)
    print("Would you like me to:")
    print("1. Generate a detailed SOC2 compliance report?")
    print("2. Create remediation scripts for the identified issues?")
    print("3. Set up continuous compliance monitoring?")
    print("4. Show me specific control details?")
    
    return results


def simple_yes_no_check():
    """
    Even simpler yes/no SOC2 compliance check
    """
    print("\n" + "=" * 60)
    print("🔍 QUICK SOC2 COMPLIANCE CHECK")
    print("=" * 60)
    print()
    
    # Run basic assessment
    results = assess_soc2_compliance()
    
    compliance_score = results['summary']['compliance_percentage']
    critical_issues = results['summary']['non_compliant']
    
    # Simple yes/no answer
    if compliance_score >= 95 and critical_issues == 0:
        print("✅ YES - Your network IS SOC2 compliant!")
        print(f"   Compliance Score: {compliance_score}%")
    else:
        print("❌ NO - Your network is NOT fully SOC2 compliant")
        print(f"   Compliance Score: {compliance_score}%")
        print(f"   Critical Issues: {critical_issues}")
        
    print("\nType 'details' for more information.")


if __name__ == "__main__":
    print("🚀 SuperSleuth Network - SOC2 Compliance Check Demo")
    print("=" * 60)
    print()
    
    # Show the natural language request
    print("👤 IT Professional: \"Check to see if my network is SOC2 compliant\"")
    print()
    
    # Run the detailed check
    results = natural_language_soc2_check()
    
    # Show the simple version too
    simple_yes_no_check()
    
    print("\n✨ Assessment complete!")
    print("\n💡 This is how Claude Code would orchestrate the SOC2 compliance check")
    print("   based on your natural language request!")