# SuperSleuth Network Workflow Examples with Claude Code

## Introduction

This guide provides step-by-step workflows showing how Claude Code orchestrates SuperSleuth tools to solve complex network problems. Each example shows the natural language interaction and the resulting diagnostic workflow.

## Workflow 1: Diagnosing Slow Website Access

### Scenario
Users report that the company website loads slowly from branch offices but works fine from headquarters.

### Natural Language Request
```
"Company website www.example.com loads slowly from branch offices but is fast from HQ. 
Branch offices use 10.20.0.0/16 subnet, HQ uses 10.10.0.0/16. Started yesterday afternoon."
```

### Claude Code Workflow

#### Step 1: DNS Resolution Analysis
```python
# Claude recognizes potential DNS issues and starts there
dns_diag = DNSDiagnostics()

# Test from branch office perspective
branch_dns_results = dns_diag.comprehensive_dns_test(
    domain="www.example.com",
    test_source="10.20.1.10"  # Branch office DNS
)

# Compare with HQ
hq_dns_results = dns_diag.comprehensive_dns_test(
    domain="www.example.com", 
    test_source="10.10.1.10"  # HQ DNS
)
```

#### Step 2: Routing Path Analysis
```python
# Check routing differences
routing_diag = RoutingDiagnostics()

branch_trace = routing_diag.enhanced_traceroute(
    "www.example.com",
    source="10.20.1.100"
)

hq_trace = routing_diag.enhanced_traceroute(
    "www.example.com",
    source="10.10.1.100"
)

# Analyze path differences
path_comparison = routing_diag.compare_routes(branch_trace, hq_trace)
```

#### Step 3: HTTP Performance Testing
```python
# Test actual HTTP performance
http_diag = HTTPDiagnostics()

branch_http = http_diag.comprehensive_http_test(
    "https://www.example.com",
    source_ip="10.20.1.100"
)

hq_http = http_diag.comprehensive_http_test(
    "https://www.example.com",
    source_ip="10.10.1.100"
)
```

#### Step 4: Network Metrics Collection
```python
# Gather overall network metrics
metrics = NetworkMetrics()

branch_metrics = metrics.collect_metrics(
    interface="branch-wan",
    duration=300  # 5 minutes
)

hq_metrics = metrics.collect_metrics(
    interface="hq-wan",
    duration=300
)
```

### Claude Code Analysis
```
Based on the diagnostics:

1. DNS Resolution: Branch offices using public DNS (8.8.8.8) with 150ms latency
   HQ using internal DNS (10.10.1.10) with 5ms latency

2. Routing: Branch traffic routes through congested ISP peer
   - 7 additional hops vs HQ
   - Packet loss at hop 5 (2.3%)

3. HTTP Performance: 
   - Branch: 8.5s page load time
   - HQ: 0.8s page load time
   - Primary delay in DNS and initial TCP handshake

Recommendations:
1. Configure branch offices to use internal DNS servers via VPN
2. Work with ISP to address congestion at peer link
3. Consider CDN for static content to serve branch users locally
```

## Workflow 2: Troubleshooting Intermittent VPN Disconnections

### Scenario
Remote users experience VPN disconnections every 30-60 minutes during business hours.

### Natural Language Request
```
"VPN users getting disconnected every 30-60 minutes during business hours. 
Affects all remote users. VPN gateway is 203.0.113.10. Started last Monday."
```

### Claude Code Workflow

#### Step 1: Port and Connectivity Analysis
```python
# Check VPN port accessibility
port_scanner = PortScanner()

# Test common VPN ports
vpn_ports = port_scanner.scan_ports(
    "203.0.113.10",
    ports=[500, 4500, 1701, 1723, 443],  # IKE, NAT-T, L2TP, PPTP, SSL
    timeout=5
)

# Monitor for intermittent issues
connectivity_monitor = port_scanner.monitor_port(
    "203.0.113.10",
    port=4500,
    duration=3600,  # 1 hour
    interval=30     # Check every 30 seconds
)
```

#### Step 2: Performance Pattern Analysis
```python
# Analyze performance patterns
perf_analyzer = PerformanceAnalyzer()

# Collect metrics during problem window
patterns = perf_analyzer.analyze_time_patterns(
    target="203.0.113.10",
    metrics=["latency", "packet_loss", "jitter"],
    window_start="09:00",
    window_end="17:00",
    granularity="5min"
)

# Identify correlation with business hours
load_correlation = perf_analyzer.correlate_with_load(patterns)
```

#### Step 3: DHCP Lease Analysis
```python
# Check for DHCP conflicts or exhaustion
dhcp_diag = DHCPDiagnostics()

# Analyze VPN IP pool
vpn_pool_status = dhcp_diag.analyze_pool(
    server="10.1.1.20",
    pool="VPN-Remote-Users"
)

# Check for lease timing issues
lease_patterns = dhcp_diag.analyze_lease_patterns(
    pool="VPN-Remote-Users",
    timeframe="7d"
)
```

#### Step 4: Advanced Network Analysis
```python
# Deep packet inspection for disconnect patterns
advanced_diag = AdvancedDiagnostics()

# Monitor for specific issues
disconnect_analysis = advanced_diag.monitor_connections(
    filter="host 203.0.113.10 and (tcp[tcpflags] & tcp-fin != 0 or tcp[tcpflags] & tcp-rst != 0)",
    duration=3600
)

# Check for MTU issues
mtu_test = advanced_diag.test_mtu_path(
    source="remote-user-subnet",
    destination="203.0.113.10"
)
```

### Claude Code Analysis
```
Diagnostic Results:

1. Connectivity: VPN ports consistently accessible
   No intermittent port blocking detected

2. Performance Patterns: 
   - CPU usage on VPN gateway spikes to 95% every 45 minutes
   - Corresponds with authentication server sync

3. DHCP Analysis:
   - VPN pool 90% utilized during business hours
   - No IP conflicts detected
   - Lease time set to 1 hour

4. Advanced Analysis:
   - TCP RST packets from VPN gateway when CPU > 90%
   - MTU mismatches causing fragmentation (1500 vs 1400)

Root Cause: VPN gateway CPU overload during LDAP sync operations

Immediate Actions:
1. Increase LDAP sync interval from 45 to 120 minutes
2. Adjust VPN client MTU to 1400
3. Schedule VPN gateway upgrade for increased capacity

Long-term Solutions:
1. Implement VPN load balancing
2. Optimize LDAP queries
3. Consider split-tunnel to reduce gateway load
```

## Workflow 3: Investigating Security Incident - Suspicious Traffic

### Scenario
Security team detected unusual outbound traffic from internal servers to unknown external IPs.

### Natural Language Request
```
"Detected suspicious outbound traffic from internal servers (10.1.50.0/24) to multiple external IPs. 
Traffic on ports 6667, 6697 (IRC). Need immediate security assessment."
```

### Claude Code Workflow

#### Step 1: Immediate Port Scan
```python
# Identify all affected systems
security_assess = SecurityAssessment()

# Scan internal subnet for IRC ports
irc_scan = security_assess.scan_subnet(
    subnet="10.1.50.0/24",
    ports=[6667, 6697, 7000],  # Common IRC ports
    aggressive=False  # Avoid disruption
)

# Identify compromised hosts
compromised = [host for host in irc_scan if host['ports_open']]
```

#### Step 2: Traffic Analysis
```python
# Analyze traffic patterns
traffic_analysis = security_assess.analyze_traffic_patterns(
    sources=compromised,
    timeframe="24h",
    focus_ports=[6667, 6697]
)

# Identify command & control patterns
c2_patterns = security_assess.detect_c2_behavior(
    traffic_analysis,
    signatures=["periodic_beacon", "data_exfiltration", "binary_transfer"]
)
```

#### Step 3: DNS Investigation
```python
# Check for malicious DNS queries
dns_diag = DNSDiagnostics()

# Analyze DNS logs for suspicious domains
suspicious_dns = dns_diag.analyze_query_logs(
    clients=compromised,
    timeframe="48h",
    check_reputation=True
)

# Look for DGA (Domain Generation Algorithm) patterns
dga_detection = dns_diag.detect_dga_domains(suspicious_dns)
```

#### Step 4: Comprehensive System Assessment
```python
# Full system evaluation
for host in compromised:
    # Check running services
    services = port_scanner.comprehensive_scan(host)
    
    # Analyze network connections
    connections = advanced_diag.get_active_connections(host)
    
    # Check for persistence mechanisms
    persistence = security_assess.check_persistence(host)
```

### Claude Code Analysis
```
Security Assessment Results:

CRITICAL FINDINGS:
1. Compromised Hosts: 3 servers identified
   - 10.1.50.15 (Web Server)
   - 10.1.50.22 (Database Server)  
   - 10.1.50.30 (File Server)

2. Traffic Analysis:
   - IRC bot communication confirmed
   - Beaconing every 5 minutes to 185.220.101.45
   - 2.3GB data exfiltrated in past 24 hours
   - Binary downloads detected (possible malware updates)

3. DNS Analysis:
   - 47 queries to known malicious domains
   - DGA pattern detected: [random].evil[.]com
   - DNS tunneling attempts identified

4. Compromise Indicators:
   - New service "SystemUpdate" running on all affected hosts
   - Outbound firewall rules modified
   - Administrator account "svcadmin" created

IMMEDIATE ACTIONS REQUIRED:
1. Isolate affected systems immediately
2. Block outbound traffic to identified C2 servers
3. Preserve forensic evidence
4. Reset all administrative credentials

Containment Commands:
# Firewall rules
iptables -A OUTPUT -d 185.220.101.45 -j DROP
iptables -A OUTPUT -p tcp --dport 6667 -j DROP
iptables -A OUTPUT -p tcp --dport 6697 -j DROP

# Null route malicious IPs
ip route add blackhole 185.220.101.45

Investigation Steps:
1. Check logs for initial compromise vector
2. Scan all systems in adjacent subnets
3. Review firewall logs for lateral movement
4. Analyze backup systems for timeline
```

## Workflow 4: Complex Performance Degradation

### Scenario
Enterprise application performance degraded across multiple sites, affecting database queries, file transfers, and API calls.

### Natural Language Request
```
"Enterprise app performance is terrible. Database queries timeout, file uploads fail at 50MB, 
API response times are 10x normal. Affects all three data centers. Started gradually over past week."
```

### Claude Code Workflow

#### Step 1: Comprehensive Baseline
```python
# Establish current performance baseline
perf_analyzer = PerformanceAnalyzer()

# Test each component
components = {
    'database': {'host': '10.1.10.50', 'port': 3306},
    'file_server': {'host': '10.1.20.50', 'port': 445},
    'api_gateway': {'host': '10.1.30.50', 'port': 443}
}

baselines = {}
for name, target in components.items():
    baselines[name] = perf_analyzer.comprehensive_test(
        host=target['host'],
        port=target['port'],
        tests=['latency', 'throughput', 'connection_time', 'stability']
    )
```

#### Step 2: Network Path Analysis
```python
# Analyze paths between components
routing_diag = RoutingDiagnostics()

# Map inter-component communication
path_analysis = routing_diag.analyze_application_paths(
    components=components,
    test_size=[64, 1500, 9000],  # Different packet sizes
    test_count=100
)

# Check for MTU issues
mtu_analysis = routing_diag.discover_path_mtu(components)
```

#### Step 3: Deep Performance Analysis
```python
# Investigate specific issues
# Database timeouts
db_analysis = advanced_diag.analyze_tcp_behavior(
    src="app_servers",
    dst="10.1.10.50:3306",
    focus="retransmissions,window_scaling,zero_windows"
)

# File transfer failures
file_analysis = advanced_diag.analyze_large_transfers(
    src="clients",
    dst="10.1.20.50",
    file_size="50MB",
    protocol="SMB"
)

# API latency
api_analysis = http_diag.analyze_api_performance(
    endpoint="https://10.1.30.50/api/v1/",
    concurrent_requests=50,
    duration=300
)
```

#### Step 4: Infrastructure Analysis
```python
# Check infrastructure components
# Network device health
topology = TopologyInterference()
device_health = topology.assess_infrastructure_health()

# QoS and traffic shaping
qos_analysis = advanced_diag.analyze_qos_policies(
    affected_subnets=["10.1.10.0/24", "10.1.20.0/24", "10.1.30.0/24"]
)

# Capacity analysis
capacity = metrics.analyze_link_utilization(
    links=["dc1-dc2", "dc2-dc3", "dc1-dc3"],
    timeframe="7d"
)
```

### Claude Code Analysis
```
Performance Degradation Analysis:

ROOT CAUSES IDENTIFIED:

1. MTU Mismatch (Primary Issue - 60% impact):
   - Jumbo frames (9000) enabled on servers
   - Inter-DC links only support 1500 MTU
   - Causing fragmentation and retransmissions
   - File transfers most affected

2. QoS Misconfiguration (30% impact):
   - Database traffic incorrectly classified as "bulk"
   - Getting de-prioritized during congestion
   - Explains timeout issues

3. Link Saturation (10% impact):
   - DC1-DC2 link at 85% utilization
   - Backup running during business hours
   - Adding 50ms latency during peaks

DETAILED FINDINGS:

Database Performance:
- Query latency: 2500ms (baseline: 250ms)
- TCP retransmissions: 12%
- Zero window events: 847/hour

File Transfers:
- Success rate <50MB: 45%
- Fragmentation rate: 78%
- Effective throughput: 10Mbps (link is 1Gbps)

API Performance:
- P95 latency: 5000ms (baseline: 500ms)
- Connection pool exhaustion events: 23/hour
- HTTP 504 timeouts: 15%

REMEDIATION PLAN:

Immediate (1 hour):
1. Disable jumbo frames on servers:
   # On each server
   ifconfig eth0 mtu 1500
   
2. Fix QoS classification:
   # On core switches
   class-map match-any DATABASE
   match dscp af41
   policy-map DC-QOS
   class DATABASE
   priority percent 30

3. Reschedule backups to 2 AM:
   # In backup software
   Schedule.setTime("02:00")

Short-term (1 day):
1. Implement TCP optimization
2. Increase connection pool sizes
3. Enable link aggregation for DC interconnects

Long-term (1 week):
1. Upgrade inter-DC links to 10Gbps
2. Implement proper MTU path discovery
3. Deploy application-aware load balancing

Expected improvement: 85% performance recovery after immediate actions
```

## Best Practices for Complex Workflows

### 1. Start Broad, Then Focus
- Begin with high-level symptoms
- Let Claude Code determine the diagnostic path
- Provide additional context as needed

### 2. Iterative Refinement
```
Initial: "Network is slow"
Refined: "Network slow for specific application"
Optimal: "Database queries from app servers timeout during business hours"
```

### 3. Provide Environmental Context
- Network topology details
- Recent changes
- Business impact
- Time patterns

### 4. Trust the Process
Claude Code will:
- Run diagnostics in optimal order
- Correlate results automatically
- Identify root causes
- Provide actionable recommendations

### 5. Follow-Up Interactions
After initial diagnosis:
- "Can you check if [specific theory] is correct?"
- "What would happen if we [proposed change]?"
- "How can we prevent this in the future?"
- "Generate a report for management"

## Conclusion

These workflows demonstrate how Claude Code transforms complex network troubleshooting into natural conversations. By understanding the patterns and providing clear context, IT professionals can leverage SuperSleuth's full power without memorizing commands or procedures.