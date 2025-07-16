#!/usr/bin/env python3
"""
SuperSleuth Network Event Logging Demonstration
Shows how events are captured from various system components
"""

import sys
import time
import threading
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.event_logger import event_logger, EventType, EventSeverity
from src.core.authorization import EnterpriseAuthorization, AuthorizationRequest
from src.core.monitoring import NetworkMonitor
from src.diagnostics.network_discovery import NetworkDiscovery


def simulate_diagnostic_events():
    """
    Simulate various diagnostic events to demonstrate logging
    """
    
    print("\n🔍 Simulating Diagnostic Events...")
    print("=" * 50)
    
    # Network discovery events
    event_logger.log_event(
        EventType.DISCOVERY,
        EventSeverity.INFO,
        "NetworkDiscovery",
        "Starting network discovery scan",
        {"subnet": "192.168.1.0/24", "method": "ARP"}
    )
    time.sleep(0.5)
    
    # Simulate device discoveries
    devices = [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "type": "router"},
        {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF", "type": "computer"},
        {"ip": "192.168.1.100", "mac": "11:22:33:44:55:66", "type": "printer"}
    ]
    
    for device in devices:
        event_logger.log_event(
            EventType.DISCOVERY,
            EventSeverity.INFO,
            "NetworkDiscovery",
            f"Discovered device: {device['type']} at {device['ip']}",
            device
        )
        time.sleep(0.3)
    
    # Performance analysis events
    event_logger.log_event(
        EventType.PERFORMANCE,
        EventSeverity.INFO,
        "PerformanceAnalysis",
        "Running bandwidth test",
        {"server": "speedtest.net", "duration": 10}
    )
    time.sleep(1)
    
    event_logger.log_event(
        EventType.PERFORMANCE,
        EventSeverity.WARNING,
        "PerformanceAnalysis",
        "Bandwidth below SLA threshold",
        {
            "measured": 45.2,
            "expected": 100.0,
            "unit": "Mbps",
            "sla_compliance": False
        }
    )
    
    print("✓ Diagnostic events simulated")


def simulate_security_events():
    """
    Simulate security-related events
    """
    
    print("\n🔒 Simulating Security Events...")
    print("=" * 50)
    
    # Authorization events
    event_logger.log_event(
        EventType.AUTHORIZATION,
        EventSeverity.INFO,
        "Authorization",
        "Authorization request received",
        {
            "user": "admin@company.com",
            "action": "run_security_scan",
            "ip": "192.168.1.50"
        }
    )
    time.sleep(0.3)
    
    # Security scan events
    event_logger.log_event(
        EventType.SECURITY,
        EventSeverity.INFO,
        "SecurityAssessment",
        "Starting vulnerability scan",
        {"scan_type": "comprehensive", "targets": 25}
    )
    time.sleep(0.5)
    
    # Security findings
    vulnerabilities = [
        {
            "severity": "high",
            "type": "open_port",
            "port": 23,
            "service": "telnet",
            "risk": "Unencrypted remote access"
        },
        {
            "severity": "medium",
            "type": "weak_encryption",
            "protocol": "WPA",
            "recommendation": "Upgrade to WPA3"
        }
    ]
    
    for vuln in vulnerabilities:
        severity = EventSeverity.CRITICAL if vuln['severity'] == 'high' else EventSeverity.WARNING
        event_logger.log_event(
            EventType.SECURITY,
            severity,
            "SecurityAssessment",
            f"Vulnerability found: {vuln['type']}",
            vuln
        )
        time.sleep(0.4)
    
    print("✓ Security events simulated")


def simulate_monitoring_events():
    """
    Simulate continuous monitoring events
    """
    
    print("\n📊 Simulating Monitoring Events...")
    print("=" * 50)
    
    # Start monitoring
    event_logger.log_event(
        EventType.MONITORING,
        EventSeverity.INFO,
        "NetworkMonitor",
        "Continuous monitoring started",
        {"interval": 60, "metrics": ["bandwidth", "latency", "packet_loss"]}
    )
    
    # Simulate metric collection over time
    for i in range(5):
        # Normal metrics
        event_logger.log_event(
            EventType.MONITORING,
            EventSeverity.DEBUG,
            "NetworkMonitor",
            "Metrics collected",
            {
                "bandwidth": 85 + i * 2,
                "latency": 25 + i,
                "packet_loss": 0.1,
                "timestamp": time.time()
            }
        )
        time.sleep(0.5)
        
        # Occasional alert
        if i == 3:
            event_logger.log_event(
                EventType.ALERT,
                EventSeverity.WARNING,
                "NetworkMonitor",
                "High latency detected",
                {
                    "current": 150,
                    "threshold": 100,
                    "duration": "2 minutes",
                    "affected_services": ["web", "api"]
                }
            )
    
    print("✓ Monitoring events simulated")


def simulate_system_events():
    """
    Simulate system-level events
    """
    
    print("\n⚙️  Simulating System Events...")
    print("=" * 50)
    
    # System startup
    event_logger.log_event(
        EventType.SYSTEM,
        EventSeverity.INFO,
        "SuperSleuth",
        "SuperSleuth Network system initialized",
        {
            "version": "1.0.0",
            "modules": ["discovery", "performance", "security", "wifi"],
            "mode": "enterprise"
        }
    )
    time.sleep(0.3)
    
    # API calls
    event_logger.log_event(
        EventType.API_CALL,
        EventSeverity.DEBUG,
        "WebDashboard",
        "API request: GET /api/metrics",
        {
            "client_ip": "127.0.0.1",
            "user_agent": "Mozilla/5.0",
            "response_time": 45
        }
    )
    
    # User actions
    event_logger.log_event(
        EventType.USER_ACTION,
        EventSeverity.INFO,
        "WebDashboard",
        "User initiated diagnostic scan",
        {
            "user": "admin",
            "diagnostic_type": "full_scan",
            "estimated_duration": 300
        }
    )
    
    print("✓ System events simulated")


def simulate_remediation_events():
    """
    Simulate remediation events
    """
    
    print("\n🔧 Simulating Remediation Events...")
    print("=" * 50)
    
    # Remediation script generation
    event_logger.log_event(
        EventType.REMEDIATION,
        EventSeverity.INFO,
        "RemediationGenerator",
        "Generating remediation scripts",
        {
            "issues_found": 5,
            "platforms": ["linux", "windows"],
            "priority": "high"
        }
    )
    time.sleep(0.5)
    
    # Remediation actions
    actions = [
        {
            "action": "close_port",
            "target": "23/tcp",
            "reason": "Security vulnerability"
        },
        {
            "action": "update_firmware",
            "device": "Router-01",
            "version": "2.5.1"
        },
        {
            "action": "optimize_channel",
            "current": 6,
            "recommended": 11,
            "reason": "Channel congestion"
        }
    ]
    
    for action in actions:
        event_logger.log_event(
            EventType.REMEDIATION,
            EventSeverity.INFO,
            "RemediationGenerator",
            f"Remediation action: {action['action']}",
            action
        )
        time.sleep(0.3)
    
    print("✓ Remediation events simulated")


def display_event_statistics():
    """
    Display event statistics
    """
    
    print("\n📊 Event Statistics")
    print("=" * 50)
    
    stats = event_logger.get_statistics(hours=1)
    
    print(f"Total events logged: {stats['total_events']}")
    print("\nEvents by type:")
    for event_type, count in stats['by_type'].items():
        print(f"  {event_type:20} : {count:3d}")
    
    print("\nEvents by severity:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity:20} : {count:3d}")
    
    print(f"\nError rate: {stats['error_rate']:.1f}%")


def main():
    """
    Main demonstration function
    """
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║           SUPERSLEUTH NETWORK EVENT LOGGING DEMO              ║
╚═══════════════════════════════════════════════════════════════╝

This demo will simulate various events from different SuperSleuth components.
To view events in real-time, run the event viewer in another terminal:

    python3 event_viewer.py -f

""")
    
    # Add file handler for persistent logging
    log_file = Path("logs") / "supersleuth_demo.log"
    event_logger.add_file_handler("demo_log", log_file)
    
    print(f"Logging events to: {log_file}\n")
    
    input("Press Enter to start the demonstration...")
    
    # Run simulations
    simulate_diagnostic_events()
    time.sleep(1)
    
    simulate_security_events()
    time.sleep(1)
    
    simulate_monitoring_events()
    time.sleep(1)
    
    simulate_system_events()
    time.sleep(1)
    
    simulate_remediation_events()
    time.sleep(1)
    
    # Display statistics
    display_event_statistics()
    
    print("\n✨ Demo completed!")
    print(f"\nView the complete log at: {log_file}")
    print("\nTo explore the events interactively, run:")
    print("  python3 event_viewer.py -f                 # Follow mode")
    print("  python3 event_viewer.py -m table           # Table view")
    print("  python3 event_viewer.py -s error           # Filter errors only")
    print("  python3 event_viewer.py -t security        # Security events only")


if __name__ == '__main__':
    main()