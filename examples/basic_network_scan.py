#!/usr/bin/env python3
"""
Basic network scan example using SuperSleuth Network
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.diagnostic import DiagnosticSuite
from src.diagnostics.network_discovery import NetworkDiscovery
from src.utils.logger import get_logger, get_audit_logger


def main():
    """Run a basic network discovery scan"""
    
    # Configure logging
    logger = get_logger("BasicNetworkScan")
    
    # Client configuration (in production, this would come from secure storage)
    client_config = {
        'client_name': 'Demo Corporation',
        'sow_reference': 'DEMO-2024-001',
        'authorized_subnets': ['192.168.1.0/24'],  # Update with your local subnet
        'compliance_requirements': ['SOC2'],
        'escalation_contacts': ['demo@supersleuth.network']
    }
    
    # Create audit logger
    audit_logger = get_audit_logger(client_config['client_name'])
    
    try:
        # Create diagnostic suite
        logger.info("Creating diagnostic suite...")
        suite = DiagnosticSuite(client_config, audit_logger)
        
        # Add network discovery diagnostic
        logger.info("Adding network discovery diagnostic...")
        discovery = NetworkDiscovery(
            config={'scan_depth': 'basic'},
            authorized_subnets=client_config['authorized_subnets']
        )
        suite.add_diagnostic(discovery)
        
        # Execute diagnostics
        logger.info("Executing diagnostics...")
        print("\n" + "="*60)
        print("🔍 SUPERSLEUTH NETWORK - DEMO SCAN")
        print("="*60)
        print(f"Client: {client_config['client_name']}")
        print(f"Authorized Subnets: {', '.join(client_config['authorized_subnets'])}")
        print("\n⚠️  This is a DEMO scan. In production, proper authorization would be required.")
        print("\nStarting network discovery...")
        print("-"*60)
        
        results = suite.execute()
        
        # Display results
        print("\n📊 SCAN RESULTS")
        print("-"*60)
        print(f"Session ID: {results['session_id']}")
        print(f"Overall Health Score: {results['overall_health_score']}/100")
        print(f"Total Diagnostics Run: {results['total_diagnostics']}")
        print(f"Successful: {results['completed']}")
        print(f"Failed: {results['failed']}")
        
        # Show discovered devices
        if results['results']:
            discovery_result = results['results'][0]
            if discovery_result['status'] == 'completed':
                device_count = discovery_result['results']['total_devices']
                print(f"\n🖥️  DEVICES DISCOVERED: {device_count}")
                
                # Show first 5 devices
                devices = discovery_result['results']['devices'][:5]
                for device in devices:
                    print(f"  • {device['ip_address']} - {device.get('hostname', 'Unknown')}")
                    if 'mac_address' in device:
                        print(f"    MAC: {device['mac_address']}")
                    if 'vendor' in device:
                        print(f"    Vendor: {device['vendor']}")
                
                if device_count > 5:
                    print(f"  ... and {device_count - 5} more devices")
        
        # Show recommendations
        if results['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in results['recommendations']:
                print(f"  • {rec}")
        
        print("\n" + "="*60)
        print("✅ Scan completed successfully!")
        print("="*60)
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        print(f"\n❌ Scan failed: {str(e)}")
    finally:
        # Close audit log
        audit_logger.close()


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                   SUPERSLEUTH NETWORK                         ║
║        Enterprise WiFi & Network Diagnostic Tool              ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  DISCLAIMER: This tool is for authorized network diagnostics only.
   Ensure you have proper authorization before scanning any network.
   
📝 Note: This demo scan will only work on your local network.
   Update the 'authorized_subnets' in the code to match your network.
""")
    
    # Check if running with appropriate privileges
    if os.geteuid() != 0 if sys.platform != "win32" else False:
        print("⚠️  Warning: Running without elevated privileges.")
        print("   Some features (like OS detection) may not work properly.")
        print("   Consider running with 'sudo' for full functionality.\n")
    
    response = input("Continue with demo scan? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        main()
    else:
        print("Scan cancelled.")