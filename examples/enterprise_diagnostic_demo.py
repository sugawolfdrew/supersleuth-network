#!/usr/bin/env python3
"""
SuperSleuth Network - Enterprise Diagnostic Demo
Demonstrates the full diagnostic workflow for IT professionals
"""

import sys
import os
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.supersleuth import SuperSleuthNetwork
from src.utils.logger import get_logger


def main():
    """Run enterprise diagnostic demo"""
    
    logger = get_logger("EnterpriseDemo")
    
    # Client configuration
    client_config = {
        'client_name': 'Acme Corporation',
        'sow_reference': 'SOW-2024-001-NetworkDiag',
        'authorized_subnets': ['192.168.1.0/24', '10.0.1.0/24'],
        'compliance_requirements': ['SOC2', 'PCI_DSS'],
        'escalation_contacts': ['john.doe@acme.com', 'security@acme.com'],
        'it_contact': 'it-support@acme.com',
        'authorized_scope': 'Branch office network infrastructure'
    }
    
    # IT technician profile
    technician_profile = {
        'name': 'Sarah Miller',
        'skill_level': 'intermediate',
        'certifications': ['Network+', 'Security+']
    }
    
    # Issue description
    issue_description = "Users reporting slow WiFi and intermittent connectivity in the west wing offices"
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                   SUPERSLEUTH NETWORK                         ║
║        Enterprise WiFi & Network Diagnostic Tool              ║
║                    DEMO MODE                                  ║
╚═══════════════════════════════════════════════════════════════╝

📋 CLIENT INFORMATION:
- Organization: Acme Corporation
- Location: Branch Office - West Wing
- Compliance: SOC2, PCI DSS
- Technician: Sarah Miller (Intermediate)

🎯 REPORTED ISSUE:
Users reporting slow WiFi and intermittent connectivity in the west wing offices

⚠️  DEMO MODE: This demonstration shows SuperSleuth capabilities
   without requiring actual network access or authorization.
""")
    
    # Initialize SuperSleuth
    supersleuth = SuperSleuthNetwork(client_config, technician_profile)
    
    # Start diagnostic session
    print("\n" + "="*60)
    session_info = supersleuth.start_diagnostic_session(issue_description)
    
    # Show diagnostic plan
    print("\n📋 DIAGNOSTIC PLAN:")
    print("-"*60)
    for i, step in enumerate(session_info['diagnostic_plan'], 1):
        print(f"{i}. {step['diagnostic'].replace('_', ' ').title()}")
        print(f"   Reason: {step['reason']}")
        print(f"   Est. Time: {step['estimated_time']}")
        print()
    
    # Simulate running diagnostics
    print("\n🔄 RUNNING DIAGNOSTICS...")
    print("-"*60)
    
    # In demo mode, we'll simulate results instead of actual scanning
    demo_results = simulate_diagnostic_results()
    
    # Process simulated results
    for diag_type, result in demo_results.items():
        supersleuth.findings[diag_type] = result
        supersleuth.diagnostics_run.append(diag_type)
        print(f"✅ Completed: {diag_type.replace('_', ' ').title()}")
    
    # Generate reports for different audiences
    print("\n📄 GENERATING REPORTS...")
    print("-"*60)
    
    # IT Professional Report
    print("\n1. Generating IT Professional Report...")
    it_report = supersleuth.generate_report('it_professional')
    report_path = supersleuth.save_report(it_report, 'it_professional')
    print(f"   ✅ Saved to: {report_path}")
    
    # Business Report
    print("\n2. Generating Executive Report...")
    business_report = supersleuth.generate_report('business')
    report_path = supersleuth.save_report(business_report, 'business')
    print(f"   ✅ Saved to: {report_path}")
    
    # Technical Report
    print("\n3. Generating Technical Deep-Dive Report...")
    tech_report = supersleuth.generate_report('technical')
    report_path = supersleuth.save_report(tech_report, 'technical')
    print(f"   ✅ Saved to: {report_path}")
    
    # Show recommendations
    print("\n💡 KEY RECOMMENDATIONS:")
    print("-"*60)
    recommendations = supersleuth.get_recommendations()
    for i, rec in enumerate(recommendations[:5], 1):  # Top 5
        print(f"{i}. {rec}")
    
    if len(recommendations) > 5:
        print(f"\n   ... and {len(recommendations) - 5} more recommendations in the full reports")
    
    # End session
    print("\n")
    summary = supersleuth.end_session()
    
    # Show sample report section
    print("\n📋 SAMPLE FROM IT PROFESSIONAL REPORT:")
    print("="*60)
    print(it_report[:1500] + "\n...\n[Full report saved to file]")
    
    print("\n✨ Demo completed! Check the 'reports' directory for full reports.")


def simulate_diagnostic_results() -> dict:
    """Simulate diagnostic results for demo purposes"""
    
    return {
        'network_discovery': {
            'status': 'completed',
            'results': {
                'total_devices': 47,
                'devices': [
                    {
                        'ip_address': '192.168.1.1',
                        'hostname': 'gateway.acme.local',
                        'mac_address': '00:11:22:33:44:55',
                        'vendor': 'Cisco Systems',
                        'device_type': 'router'
                    },
                    {
                        'ip_address': '192.168.1.10',
                        'hostname': 'ap-westwing-01',
                        'mac_address': '00:11:22:33:44:66',
                        'vendor': 'Ubiquiti Networks',
                        'device_type': 'access_point'
                    }
                ],
                'network_map': {
                    'subnets': {
                        '192.168.1.0/24': {
                            'devices': [],
                            'device_count': 35,
                            'utilization': 13.7
                        }
                    },
                    'device_types': {
                        'windows_pc': 25,
                        'access_point': 3,
                        'printer': 5,
                        'unknown': 3
                    }
                },
                'analysis': {
                    'unknown_devices': ['192.168.1.157', '192.168.1.201', '192.168.1.245'],
                    'potential_issues': [
                        {
                            'type': 'unknown_devices',
                            'severity': 'medium',
                            'description': '3 unidentified devices detected'
                        }
                    ]
                }
            },
            'recommendations': [
                'Investigate 3 unknown devices: 192.168.1.157, 192.168.1.201, 192.168.1.245',
                'Implement network access control (NAC) to manage device connections'
            ]
        },
        
        'performance_analysis': {
            'status': 'completed',
            'results': {
                'performance_metrics': {
                    'bandwidth': {
                        'download_mbps': 87.5,
                        'upload_mbps': 22.3,
                        'ping_ms': 28
                    },
                    'latency': {
                        'local_gateway': {'avg_ms': 2, 'min_ms': 1, 'max_ms': 5},
                        'public_dns': {'avg_ms': 28, 'min_ms': 25, 'max_ms': 45}
                    },
                    'packet_loss': {
                        'gateway': {'loss_percent': 0.0},
                        'internet': {'loss_percent': 0.5}
                    },
                    'jitter': {
                        'avg_jitter_ms': 3.2,
                        'max_jitter_ms': 8.5
                    }
                },
                'sla_validation': {
                    'compliant': False,
                    'violations': [
                        {
                            'metric': 'download_bandwidth',
                            'threshold': 100,
                            'actual': 87.5,
                            'severity': 'high'
                        }
                    ]
                },
                'overall_score': 78
            },
            'recommendations': [
                'Upgrade internet connection - current 87.5 Mbps is below SLA requirement of 100 Mbps',
                'Implement QoS prioritization for business-critical applications'
            ]
        },
        
        'wifi_analysis': {
            'status': 'completed',
            'results': {
                'networks_found': 12,
                'current_connection': {
                    'ssid': 'AcmeCorp-Office',
                    'channel': 6,
                    'rssi': -72,
                    'signal_quality': 60
                },
                'channel_analysis': {
                    '2.4GHz': {
                        'networks_count': 8,
                        'best_channels': [11, 1, 6],
                        'channel_congestion': {6: 4, 1: 2, 11: 2}
                    },
                    'recommendations': [
                        {
                            'band': '2.4GHz',
                            'recommended_channels': [11],
                            'reason': 'Channel 6 is congested with 4 networks'
                        }
                    ]
                },
                'signal_analysis': {
                    'coverage_issues': [
                        {
                            'type': 'weak_signal',
                            'network': 'AcmeCorp-Office',
                            'rssi': -78,
                            'location': 'West wing offices'
                        }
                    ]
                },
                'security_analysis': {
                    'security_distribution': {
                        'wpa2': 10,
                        'wpa3': 1,
                        'open': 1
                    },
                    'security_issues': [
                        {
                            'severity': 'medium',
                            'type': 'outdated_encryption',
                            'network': 'AcmeCorp-Office',
                            'message': 'Consider upgrading to WPA3 for enhanced security'
                        }
                    ]
                }
            },
            'recommendations': [
                'Switch 2.4GHz to channel 11 to reduce interference',
                'Deploy additional access points to address coverage gaps in west wing',
                'Upgrade WiFi security from WPA2 to WPA3'
            ]
        },
        
        'security_assessment': {
            'status': 'completed',
            'results': {
                'overall_risk_score': 35,
                'network_security': {
                    'firewall_status': {'enabled': True, 'type': 'pfSense'},
                    'open_ports': [
                        {'port': 445, 'service': 'SMB', 'risk': 'medium'}
                    ],
                    'security_issues': [
                        {
                            'type': 'open_vulnerable_port',
                            'severity': 'medium',
                            'port': 445,
                            'service': 'SMB',
                            'message': 'Port 445 (SMB) is open and may pose security risk'
                        }
                    ]
                },
                'compliance_status': {
                    'overall_compliant': False,
                    'framework_results': {
                        'SOC2': {'compliant': True, 'gaps': []},
                        'PCI_DSS': {
                            'compliant': False,
                            'gaps': [
                                {
                                    'requirement': 'PCI DSS 4.1',
                                    'description': 'WiFi must use WPA3 encryption',
                                    'severity': 'high'
                                }
                            ]
                        }
                    }
                }
            },
            'recommendations': [
                'CRITICAL: Close or secure port 445 (SMB) to prevent unauthorized access',
                'Compliance Gap (PCI DSS 4.1): Upgrade WiFi encryption to WPA3',
                'Implement regular security assessments and penetration testing'
            ]
        }
    }


if __name__ == "__main__":
    main()