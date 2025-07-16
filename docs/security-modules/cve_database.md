# CVE Database Module Documentation

## Overview

The `cve_database` module provides functions for querying and caching CVE (Common Vulnerabilities and Exposures) data. It includes a local SQLite cache to reduce API calls and improve performance.

## Core Functions

### CVE Search Functions

#### `search_cve_by_id(cve_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]`

Searches for a specific CVE by its identifier.

**Parameters:**
- `cve_id` (str): CVE identifier (e.g., 'CVE-2021-44228')
- `use_cache` (bool): Whether to use cached data if available (default: True)

**Returns:**
- Dictionary containing CVE details or None if not found
  - `cve_id`: CVE identifier
  - `description`: Vulnerability description
  - `cvss_v3_score`: CVSS v3 score (0-10)
  - `severity`: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
  - `published_date`: Publication date
  - `references`: List of reference URLs
  - `cpe_matches`: Affected products (CPE format)

**Example:**
```python
cve = search_cve_by_id('CVE-2021-44228')
if cve:
    print(f"Log4j vulnerability: {cve['description']}")
    print(f"Severity: {cve['severity']} (CVSS: {cve['cvss_v3_score']})")
```

**When to use:** Looking up details of a known CVE.

---

#### `search_cves_by_keyword(keyword: str, severity: str = None, limit: int = 50) -> List[Dict[str, Any]]`

Searches CVEs by keyword in description.

**Parameters:**
- `keyword` (str): Search term
- `severity` (str): Filter by severity ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
- `limit` (int): Maximum results to return (default: 50)

**Returns:**
- List of matching CVE records, sorted by CVSS score

**Example:**
```python
# Find critical Apache vulnerabilities
apache_cves = search_cves_by_keyword('Apache', severity='CRITICAL', limit=10)
for cve in apache_cves:
    print(f"{cve['cve_id']}: {cve['description'][:80]}...")
```

**When to use:** Discovering vulnerabilities related to a technology.

---

#### `search_cves_by_service(service_name: str, version: str = None, include_lower_versions: bool = True) -> List[Dict[str, Any]]`

Searches CVEs affecting a specific service or software.

**Parameters:**
- `service_name` (str): Name of the service (e.g., 'Apache', 'nginx', 'OpenSSH')
- `version` (str): Specific version to check (optional)
- `include_lower_versions` (bool): Include CVEs for lower versions (default: True)

**Returns:**
- List of CVEs affecting the service, sorted by CVSS score

**Example:**
```python
# Check if Apache 2.4.49 is vulnerable
cves = search_cves_by_service('Apache', '2.4.49')
if cves:
    print(f"Found {len(cves)} vulnerabilities for Apache 2.4.49")
    
# Check all nginx vulnerabilities
nginx_cves = search_cves_by_service('nginx')
```

**When to use:** Checking if detected services have known vulnerabilities.

### Batch Operations

#### `check_vulnerabilities_batch(services: List[Dict[str, str]]) -> Dict[str, List[Dict[str, Any]]]`

Checks vulnerabilities for multiple services at once.

**Parameters:**
- `services` (List[Dict]): List of services with 'name' and 'version' keys

**Returns:**
- Dictionary mapping service identifiers to their CVEs

**Example:**
```python
services = [
    {'name': 'Apache', 'version': '2.4.49'},
    {'name': 'OpenSSH', 'version': '7.4'},
    {'name': 'MySQL', 'version': '5.7.20'}
]
vulns = check_vulnerabilities_batch(services)

for service_key, cves in vulns.items():
    print(f"{service_key}: {len(cves)} vulnerabilities found")
```

**When to use:** Checking multiple services after network scanning.

### Risk Assessment Functions

#### `calculate_risk_score(cve_data: Dict[str, Any], asset_criticality: int = 5, exposure_level: int = 5) -> Dict[str, Any]`

Calculates risk score for a CVE based on CVSS and environmental factors.

**Parameters:**
- `cve_data` (Dict): CVE information including CVSS scores
- `asset_criticality` (int): Asset criticality rating (1-10)
- `exposure_level` (int): Network exposure level (1-10)

**Returns:**
- Dictionary containing:
  - `cve_id`: CVE identifier
  - `base_cvss`: Original CVSS score
  - `risk_score`: Calculated risk score (0-10)
  - `risk_level`: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
  - `recommendation`: Risk-based recommendation

**Example:**
```python
cve = search_cve_by_id('CVE-2021-44228')
# Critical server, exposed to internet
risk = calculate_risk_score(cve, asset_criticality=10, exposure_level=10)
print(f"Risk Level: {risk['risk_level']} (Score: {risk['risk_score']})")
print(f"Recommendation: {risk['recommendation']}")
```

**When to use:** Prioritizing vulnerabilities based on context.

### Statistics and Analysis

#### `get_cve_statistics(start_date: str = None, end_date: str = None) -> Dict[str, Any]`

Gets CVE statistics for a date range.

**Parameters:**
- `start_date` (str): Start date in ISO format (optional)
- `end_date` (str): End date in ISO format (optional)

**Returns:**
- Dictionary containing:
  - `total`: Total CVE count
  - `by_severity`: Count by severity level
  - `average_cvss_score`: Average CVSS score
  - `date_range`: Query date range

**Example:**
```python
# Get statistics for 2023
stats = get_cve_statistics('2023-01-01', '2023-12-31')
print(f"Total CVEs in 2023: {stats['total']}")
print(f"Critical: {stats['by_severity'].get('CRITICAL', 0)}")
```

**When to use:** Understanding vulnerability trends.

## Database Management

### Database Location

The CVE database is stored in the user's home directory:
- Path: `~/.supersleuth/cve/cve_cache.db`
- Automatically created on first use

### Cache Management

```python
# Force fresh data (bypass cache)
cve = search_cve_by_id('CVE-2021-44228', use_cache=False)

# Cache is automatically managed:
# - CVE data cached for 7 days
# - Automatic cache invalidation
# - No manual cleanup needed
```

### Syncing CVE Data

#### `sync_nvd_feed(year: int = None, api_key: str = None) -> Dict[str, Any]`

Syncs CVE data from NVD feeds (requires implementation of actual NVD API).

**Parameters:**
- `year` (int): Year to sync (default: current year)
- `api_key` (str): NVD API key (required for API 2.0)

**Returns:**
- Sync statistics

**Note:** Current implementation uses sample data. Production use requires NVD API integration.

## Common Usage Patterns

### Pattern 1: Post-Scan Vulnerability Check
```python
# After detecting services
services = [
    {'name': 'Apache', 'version': '2.4.49'},
    {'name': 'OpenSSH', 'version': '8.0'}
]

# Check for vulnerabilities
for service in services:
    cves = search_cves_by_service(service['name'], service['version'])
    if cves:
        # Calculate risk for each CVE
        for cve in cves[:5]:  # Top 5
            risk = calculate_risk_score(cve, asset_criticality=7)
            print(f"{cve['cve_id']}: {risk['risk_level']} - {risk['recommendation']}")
```

### Pattern 2: Targeted CVE Investigation
```python
# IT Professional: "Are we vulnerable to Log4Shell?"
log4shell = search_cve_by_id('CVE-2021-44228')
if log4shell:
    # Search for affected services
    affected = search_cves_by_keyword('log4j')
    print(f"Log4Shell affects: {log4shell['description']}")
    print(f"Found {len(affected)} related vulnerabilities")
```

### Pattern 3: Compliance Reporting
```python
# Get high/critical vulnerabilities for audit
critical_cves = search_cves_by_keyword('', severity='CRITICAL', limit=100)
high_cves = search_cves_by_keyword('', severity='HIGH', limit=100)

print(f"Security Audit Summary:")
print(f"- Critical vulnerabilities: {len(critical_cves)}")
print(f"- High vulnerabilities: {len(high_cves)}")
```

## Performance Considerations

- **Caching**: All queries check local cache first (7-day TTL)
- **Batch Operations**: Use batch functions for multiple queries
- **Rate Limiting**: Built-in delays for API calls
- **Database Indexes**: Optimized for common query patterns

## Data Sources

Currently implemented:
- Local SQLite cache
- Sample CVE data for common vulnerabilities

Future implementation:
- NVD (National Vulnerability Database) API
- MITRE CVE database
- Vendor-specific vulnerability feeds

## Integration with Other Modules

The CVE database integrates with:
- **Security Scanner**: Enriches service detection with vulnerability data
- **Vulnerability Reporter**: Provides CVE details for reports
- **Risk Assessment**: Enables contextual risk scoring

## Error Handling

All functions handle errors gracefully:
- Database connection failures
- Missing CVE data
- Invalid input parameters
- Network timeouts (for API calls)

Functions return None or empty lists rather than raising exceptions.

## Best Practices

1. **Use Caching**: Keep `use_cache=True` for better performance
2. **Batch Queries**: Use `check_vulnerabilities_batch()` for multiple services
3. **Risk Context**: Always consider asset criticality and exposure
4. **Version Specificity**: Provide exact versions when available
5. **Regular Updates**: Sync CVE data periodically (when implemented)