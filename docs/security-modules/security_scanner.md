# Security Scanner Module Documentation

## Overview

The `security_scanner` module provides modular functions for network security scanning that Claude Code can orchestrate based on IT professional needs. All functions are designed to be safe, non-intrusive, and suitable for production environments.

## Core Functions

### Port Scanning Functions

#### `scan_tcp_port(host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]`

Scans a single TCP port on a target host.

**Parameters:**
- `host` (str): Target hostname or IP address
- `port` (int): Port number to scan
- `timeout` (float): Connection timeout in seconds (default: 1.0)

**Returns:**
- Dictionary containing:
  - `host`: Target host
  - `port`: Port number
  - `state`: 'open', 'closed', 'filtered', or 'error'
  - `latency`: Connection time (if successful)
  - `error`: Error message (if any)
  - `timestamp`: ISO format timestamp

**Example:**
```python
result = scan_tcp_port('192.168.1.1', 80)
# {'host': '192.168.1.1', 'port': 80, 'state': 'open', 'latency': 0.023}
```

**When to use:** Quick check of a specific service port.

---

#### `scan_tcp_ports_batch(host: str, ports: List[int], timeout: float = 1.0, max_workers: int = 50) -> List[Dict[str, Any]]`

Scans multiple TCP ports in parallel using a thread pool.

**Parameters:**
- `host` (str): Target hostname or IP address
- `ports` (List[int]): List of port numbers to scan
- `timeout` (float): Connection timeout per port (default: 1.0)
- `max_workers` (int): Maximum concurrent connections (default: 50)

**Returns:**
- List of port scan results, sorted by port number

**Example:**
```python
results = scan_tcp_ports_batch('192.168.1.1', [80, 443, 22, 3389])
open_ports = [r for r in results if r['state'] == 'open']
```

**When to use:** Checking multiple specific ports efficiently.

---

#### `scan_tcp_range(host: str, start_port: int = 1, end_port: int = 1024, timeout: float = 1.0, max_workers: int = 50) -> List[Dict[str, Any]]`

Scans a range of TCP ports.

**Parameters:**
- `host` (str): Target hostname or IP address
- `start_port` (int): First port in range (default: 1)
- `end_port` (int): Last port in range, inclusive (default: 1024)
- `timeout` (float): Connection timeout per port
- `max_workers` (int): Maximum concurrent connections

**Returns:**
- List of scan results for all ports in range

**Example:**
```python
# Scan well-known ports
results = scan_tcp_range('192.168.1.1', 1, 1024)
```

**When to use:** Discovering services on unknown systems.

---

#### `scan_common_ports(host: str, service_type: str = 'all', timeout: float = 1.0) -> List[Dict[str, Any]]`

Scans commonly used ports based on service category.

**Parameters:**
- `host` (str): Target hostname or IP address
- `service_type` (str): Category of services to scan
  - 'web': HTTP/HTTPS ports
  - 'database': Database service ports
  - 'remote': Remote access ports
  - 'mail': Email service ports
  - 'all': All common ports
- `timeout` (float): Connection timeout per port

**Returns:**
- List of scan results with service annotations

**Example:**
```python
# Scan for database services
db_results = scan_common_ports('192.168.1.1', 'database')
```

**When to use:** Quick assessment of specific service categories.

### Service Detection Functions

#### `detect_service_banner(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]`

Attempts to grab service banner and identify the service.

**Parameters:**
- `host` (str): Target hostname or IP address
- `port` (int): Port number to probe
- `timeout` (float): Connection timeout (default: 3.0)

**Returns:**
- Dictionary containing:
  - `host`: Target host
  - `port`: Port number
  - `banner`: Raw banner text (if captured)
  - `service`: Identified service type
  - `version`: Service version (if detected)
  - `error`: Error message (if any)

**Example:**
```python
service = detect_service_banner('192.168.1.1', 22)
# {'service': 'SSH', 'version': '2.0', 'banner': 'SSH-2.0-OpenSSH_8.9'}
```

**When to use:** Identifying what service is running on an open port.

---

#### `detect_services_batch(host: str, ports: List[int], timeout: float = 3.0, max_workers: int = 10) -> List[Dict[str, Any]]`

Detects services on multiple ports in parallel.

**Parameters:**
- `host` (str): Target hostname or IP address
- `ports` (List[int]): List of ports to probe
- `timeout` (float): Connection timeout per port
- `max_workers` (int): Maximum concurrent connections

**Returns:**
- List of service detection results

**Example:**
```python
open_ports = [80, 443, 22]
services = detect_services_batch('192.168.1.1', open_ports)
```

**When to use:** Identifying services after port scanning.

### Vulnerability Checking Functions

#### `check_weak_services(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]`

Analyzes scan results for potentially vulnerable services.

**Parameters:**
- `scan_results` (List[Dict]): Port scan results to analyze

**Returns:**
- List of identified vulnerabilities with:
  - `type`: 'weak_service'
  - `host`: Affected host
  - `port`: Affected port
  - `service`: Service name
  - `risk_level`: 'critical', 'high', 'medium', or 'low'
  - `issue`: Description of the security issue
  - `recommendation`: Remediation advice

**Example:**
```python
scan_results = scan_common_ports('192.168.1.1', 'all')
vulnerabilities = check_weak_services(scan_results)
```

**When to use:** Quick identification of risky services.

---

#### `check_ssl_certificate(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]`

Validates SSL/TLS certificate on a service.

**Parameters:**
- `host` (str): Target hostname or IP address
- `port` (int): Port number (default: 443)
- `timeout` (float): Connection timeout

**Returns:**
- Dictionary containing:
  - `host`: Target host
  - `port`: Port number
  - `valid`: Boolean indicating certificate validity
  - `issues`: List of identified issues
  - `certificate`: Certificate details (subject, issuer, dates, etc.)
  - `error`: Error message (if any)

**Example:**
```python
cert_check = check_ssl_certificate('example.com', 443)
if cert_check['issues']:
    print("Certificate problems found!")
```

**When to use:** Validating HTTPS services and other SSL/TLS endpoints.

### High-Level Orchestration Functions

#### `perform_security_scan(target: str, scan_type: str = 'basic', options: Dict[str, Any] = None) -> Dict[str, Any]`

Performs a complete security scan based on scan type.

**Parameters:**
- `target` (str): Target hostname or IP address
- `scan_type` (str): Type of scan to perform
  - 'quick': Top 20 ports only
  - 'basic': Common services
  - 'web': Web-focused scan
  - 'full': Comprehensive scan (1000 ports)
- `options` (Dict): Additional options for customization

**Returns:**
- Comprehensive scan results including:
  - `port_scan`: Port scan results
  - `services`: Detected services
  - `vulnerabilities`: Identified vulnerabilities
  - `ssl_checks`: SSL/TLS validation results
  - `recommendations`: Security recommendations

**Example:**
```python
# Quick security assessment
results = perform_security_scan('192.168.1.1', 'quick')

# Full comprehensive scan
results = perform_security_scan('192.168.1.1', 'full')
```

**When to use:** Complete security assessment with minimal configuration.

## Common Usage Patterns

### Pattern 1: Quick Security Check
```python
# For "Is this server secure?" questions
target = '192.168.1.100'
results = perform_security_scan(target, 'quick')
print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
```

### Pattern 2: Service-Specific Assessment
```python
# For "Check if our web server is secure"
web_ports = scan_common_ports(target, 'web')
open_web_ports = [p for p in web_ports if p['state'] == 'open']

for port_info in open_web_ports:
    if port_info['port'] in [443, 8443]:
        cert_check = check_ssl_certificate(target, port_info['port'])
        print(f"SSL on port {port_info['port']}: {'Valid' if cert_check['valid'] else 'Invalid'}")
```

### Pattern 3: Compliance Scanning
```python
# For "We need a compliance scan"
results = perform_security_scan(target, 'full')

# Check for specific compliance issues
telnet_open = any(p['port'] == 23 and p['state'] == 'open' 
                  for p in results['port_scan'])
if telnet_open:
    print("FAIL: Telnet is enabled (violates most compliance standards)")
```

## Performance Considerations

- **Timeouts**: Adjust based on network latency (LAN: 0.5-1s, WAN: 2-5s)
- **Concurrency**: Default 50 workers is safe for most networks
- **Rate Limiting**: Built-in delays prevent overwhelming targets
- **Resource Usage**: Full scans can take several minutes

## Security and Safety

- All functions use standard TCP connect scans (no SYN stealth)
- No exploitation or vulnerability testing
- Proper error handling for all network conditions
- Audit trail support through timestamps
- Rate limiting to prevent DoS conditions

## Error Handling

All functions handle common errors gracefully:
- DNS resolution failures
- Connection timeouts
- Permission denied errors
- Network unreachable conditions

Errors are returned in the result dictionary rather than raising exceptions.

## Integration with Other Modules

The security scanner integrates with:
- **CVE Database**: Service versions can be checked for CVEs
- **Vulnerability Reporter**: Scan results can be formatted into reports
- **Security Assessment**: Provides core scanning for assessment class