"""
SuperSleuth Network Diagnostics Package

This package contains specialized diagnostic modules for network troubleshooting.
"""

from .dhcp_diagnostics import (
    DHCPDiagnostics,
    discover_dhcp_servers,
    check_ip_conflicts,
    get_lease_info,
    find_rogue_dhcp_servers,
    test_dhcp_renewal,
    diagnose_dhcp_issue
)

from .http_diagnostics import (
    test_http_endpoint,
    test_response_time,
    validate_ssl_certificate,
    analyze_http_headers,
    test_authentication,
    test_api_endpoint,
    diagnose_web_issue
)

from .routing_diagnostics import (
    RoutingDiagnostics,
    analyze_routes,
    check_gateway,
    trace_route,
    discover_mtu,
    monitor_route,
    check_asymmetric_routing
)

from .advanced_diagnostics import (
    AdvancedDiagnostics,
    process_analysis,
    system_bottleneck_detection,
    historical_trend_analysis,
    anomaly_detection,
    diagnose_slow_system
)

__all__ = [
    # DHCP diagnostics
    'DHCPDiagnostics',
    'discover_dhcp_servers',
    'check_ip_conflicts',
    'get_lease_info',
    'find_rogue_dhcp_servers',
    'test_dhcp_renewal',
    'diagnose_dhcp_issue',
    # HTTP diagnostics
    'test_http_endpoint',
    'test_response_time',
    'validate_ssl_certificate',
    'analyze_http_headers',
    'test_authentication',
    'test_api_endpoint',
    'diagnose_web_issue',
    # Routing diagnostics
    'RoutingDiagnostics',
    'analyze_routes',
    'check_gateway',
    'trace_route',
    'discover_mtu',
    'monitor_route',
    'check_asymmetric_routing',
    # Advanced diagnostics
    'AdvancedDiagnostics',
    'process_analysis',
    'system_bottleneck_detection',
    'historical_trend_analysis',
    'anomaly_detection',
    'diagnose_slow_system'
]