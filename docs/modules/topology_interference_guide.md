# Topology and Interference Diagnostics Guide

## Overview

The Topology and Interference Diagnostics module provides comprehensive tools for diagnosing common WiFi and network issues in real-world IT environments. It helps identify problems with WiFi placement, interference, network topology, and signal quality.

## Key Features

### 1. WiFi Placement Analysis
- **Signal Strength Mapping**: Maps signal strength across detected access points
- **Dead Zone Detection**: Identifies areas with weak or no signal
- **Coverage Analysis**: Categorizes coverage into excellent, good, fair, weak, and dead zones
- **AP Placement Recommendations**: Suggests optimal access point placement

### 2. Interference Detection
- **Co-Channel Interference**: Detects multiple APs on the same channel
- **Adjacent Channel Interference**: Identifies interference from neighboring channels
- **Channel Utilization Analysis**: Shows which channels are overcrowded
- **Bandwidth Overlap Detection**: Finds APs using wide channels that overlap

### 3. Network Topology Discovery
- **Automatic Network Mapping**: Discovers devices on the network
- **Device Type Detection**: Identifies routers, switches, printers, etc.
- **Latency Measurement**: Measures response time to network devices
- **Path Tracing**: Maps network paths between devices

### 4. Signal Quality Metrics
- **SNR Calculation**: Signal-to-Noise Ratio analysis
- **Speed Estimation**: Estimates achievable data rates
- **Retry/Error Rates**: Calculates packet retry and error rates
- **MCS Index**: Determines modulation and coding scheme

## Usage

### Basic Usage

```python
from src.diagnostics.topology_interference import TopologyInterferenceDiagnostics

# Create diagnostics instance
diagnostics = TopologyInterferenceDiagnostics()

# Scan WiFi networks
networks = diagnostics.scan_wifi_networks()

# Analyze interference
interference = diagnostics.analyze_interference()

# Generate coverage map
coverage = diagnostics.generate_coverage_map()

# Get recommendations
recommendations = diagnostics.recommend_ap_placement()
```

### Diagnosing Specific Issues

```python
# Diagnose slow WiFi
diagnosis = diagnostics.diagnose_issue("slow_wifi")

# Diagnose random disconnections
diagnosis = diagnostics.diagnose_issue("random_disconnections")

# Diagnose connection problems
diagnosis = diagnostics.diagnose_issue("cannot_connect")

# Diagnose time-based slowdowns
diagnosis = diagnostics.diagnose_issue("time_based_slowdown")
```

### Generating Reports

```python
# Generate comprehensive report
report = diagnostics.generate_report()

# Save to file
import json
with open('network_report.json', 'w') as f:
    json.dump(report, f, indent=2)
```

## Common Scenarios

### Scenario 1: "WiFi is slow in conference room"

**Symptoms**: 
- Slow speeds in specific location
- Good signal strength but poor performance

**Diagnostics**:
1. Check for co-channel interference
2. Analyze channel utilization
3. Measure signal quality (SNR)
4. Look for hidden interference sources

**Solutions**:
- Change to less crowded channel
- Adjust AP transmission power
- Add additional AP if coverage is weak
- Switch to 5GHz band if available

### Scenario 2: "Random disconnections"

**Symptoms**:
- Devices randomly lose connection
- Connection drops when moving between rooms

**Diagnostics**:
1. Check signal stability
2. Analyze roaming behavior
3. Look for APs with similar signal strengths
4. Check for authentication issues

**Solutions**:
- Adjust AP power for clear roaming boundaries
- Update device drivers
- Check for firmware updates
- Configure proper roaming thresholds

### Scenario 3: "Can't connect in certain areas"

**Symptoms**:
- No WiFi signal in specific locations
- Very weak signal in some areas

**Diagnostics**:
1. Generate coverage map
2. Identify dead zones
3. Analyze AP placement
4. Check for physical obstructions

**Solutions**:
- Add access points to cover dead zones
- Relocate existing APs
- Use WiFi extenders or mesh systems
- Remove physical obstructions if possible

### Scenario 4: "Network slows down at certain times"

**Symptoms**:
- Performance degrades during specific hours
- Intermittent slowdowns

**Diagnostics**:
1. Monitor channel utilization over time
2. Track number of connected devices
3. Check for scheduled tasks
4. Analyze bandwidth usage patterns

**Solutions**:
- Implement QoS policies
- Schedule backups during off-hours
- Add capacity for peak times
- Use band steering to distribute load

## Platform Support

The module supports multiple platforms with platform-specific implementations:

- **macOS**: Uses `airport` utility and `networksetup`
- **Linux**: Uses `iwlist` and `iwconfig` (requires wireless-tools)
- **Windows**: Uses `netsh wlan` commands

Some features may require elevated privileges (sudo/admin).

## Recommendations Engine

The module provides intelligent recommendations based on:

1. **Coverage Analysis**: Suggests AP placement for optimal coverage
2. **Interference Mitigation**: Recommends channel changes to reduce interference
3. **Capacity Planning**: Identifies when additional APs are needed
4. **Band Optimization**: Suggests using 5GHz for better performance

## Best Practices

1. **Regular Monitoring**: Run diagnostics periodically to catch issues early
2. **Document Changes**: Keep track of channel and placement changes
3. **Test After Changes**: Verify improvements after implementing recommendations
4. **Consider Environment**: Account for physical layout and materials
5. **Plan for Growth**: Design network with future expansion in mind

## Troubleshooting

### "No WiFi networks detected"
- Check if WiFi adapter is enabled
- Verify necessary permissions (may need sudo)
- Ensure WiFi drivers are installed

### "Cannot discover network topology"
- Check firewall settings
- Verify ICMP is not blocked
- Ensure proper network permissions

### "Incomplete interference analysis"
- Some APs may not broadcast all information
- Hidden SSIDs won't appear in scans
- Non-WiFi interference requires spectrum analyzer

## Integration with SuperSleuth Network

This module integrates with other SuperSleuth components:

- **Network Monitor**: Correlates performance with interference
- **Alert System**: Triggers alerts on coverage issues
- **Dashboard**: Visualizes topology and coverage maps
- **Historical Analysis**: Tracks interference patterns over time

## Future Enhancements

Planned improvements include:

1. **Spectrum Analysis**: Detect non-WiFi interference
2. **Predictive Modeling**: Forecast coverage before AP placement
3. **Auto-Channel Selection**: Automatically optimize channel assignment
4. **3D Coverage Maps**: Visualize coverage in multi-floor buildings
5. **IoT Device Detection**: Identify and categorize IoT devices