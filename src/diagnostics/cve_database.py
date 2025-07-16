"""
CVE Database Integration Module

This module provides functions to query and cache CVE (Common Vulnerabilities and Exposures)
data from various sources, designed for Claude Code orchestration.
"""

import json
import sqlite3
import requests
import gzip
import io
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import time
import os
from pathlib import Path

from ..utils.logger import get_logger

logger = get_logger(__name__)


class CVEDatabase:
    """Local CVE database with caching and NVD integration."""
    
    def __init__(self, db_path: str = None):
        """Initialize CVE database."""
        if db_path is None:
            # Create in user's home directory
            home = Path.home()
            db_dir = home / '.supersleuth' / 'cve'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'cve_cache.db')
            
        self.db_path = db_path
        self.conn = None
        self._init_database()
        
    def _init_database(self):
        """Initialize database schema."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        # CVE main table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                cvss_v2_score REAL,
                cvss_v2_vector TEXT,
                severity TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                cve_references TEXT,
                cpe_matches TEXT,
                cwe_ids TEXT,
                last_fetched TEXT
            )
        ''')
        
        # Service to CVE mapping
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_cves (
                service_name TEXT,
                version TEXT,
                cve_id TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_service_name ON service_cves(service_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_severity ON cves(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_score ON cves(cvss_v3_score)')
        
        self.conn.commit()
        
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


# Standalone CVE lookup functions
def search_cve_by_id(cve_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
    """
    Search for a specific CVE by ID.
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2021-44228')
        use_cache: Whether to use cached data if available
        
    Returns:
        dict: CVE details or None if not found
        
    Example:
        >>> cve = search_cve_by_id('CVE-2021-44228')
        >>> print(f"{cve['cve_id']}: {cve['description']}")
    """
    db = CVEDatabase()
    
    try:
        if use_cache:
            # Try cache first
            cursor = db.conn.cursor()
            cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,))
            row = cursor.fetchone()
            
            if row:
                # Check if cache is fresh (less than 7 days old)
                last_fetched = datetime.fromisoformat(row['last_fetched'])
                if datetime.now() - last_fetched < timedelta(days=7):
                    return _row_to_dict(row)
        
        # Fetch from NVD API
        cve_data = _fetch_cve_from_nvd(cve_id)
        if cve_data:
            _cache_cve(db, cve_data)
            return cve_data
            
        return None
        
    finally:
        db.close()


def search_cves_by_keyword(keyword: str, 
                          severity: str = None,
                          limit: int = 50) -> List[Dict[str, Any]]:
    """
    Search CVEs by keyword in description.
    
    Args:
        keyword: Search term
        severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        limit: Maximum results to return
        
    Returns:
        list: Matching CVE records
    """
    db = CVEDatabase()
    
    try:
        query = '''
            SELECT * FROM cves 
            WHERE description LIKE ? 
        '''
        params = [f'%{keyword}%']
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity.upper())
            
        query += ' ORDER BY cvss_v3_score DESC LIMIT ?'
        params.append(limit)
        
        cursor = db.conn.cursor()
        cursor.execute(query, params)
        
        results = []
        for row in cursor.fetchall():
            results.append(_row_to_dict(row))
            
        # If no results in cache, try fetching from NVD
        if not results:
            logger.info(f"No cached results for '{keyword}', fetching from NVD...")
            nvd_results = _search_nvd_by_keyword(keyword, limit)
            for cve_data in nvd_results:
                _cache_cve(db, cve_data)
                if not severity or cve_data.get('severity', '').upper() == severity.upper():
                    results.append(cve_data)
                    
        return results[:limit]
        
    finally:
        db.close()


def search_cves_by_service(service_name: str, 
                          version: str = None,
                          include_lower_versions: bool = True) -> List[Dict[str, Any]]:
    """
    Search CVEs affecting a specific service/software.
    
    Args:
        service_name: Name of the service (e.g., 'Apache', 'nginx', 'OpenSSH')
        version: Specific version to check
        include_lower_versions: Include CVEs for lower versions
        
    Returns:
        list: CVEs affecting the service
        
    Example:
        >>> cves = search_cves_by_service('Apache', '2.4.49')
        >>> for cve in cves:
        >>>     print(f"{cve['cve_id']}: {cve['severity']}")
    """
    db = CVEDatabase()
    
    try:
        # First check cache
        cursor = db.conn.cursor()
        
        if version:
            query = '''
                SELECT DISTINCT c.* FROM cves c
                JOIN service_cves sc ON c.cve_id = sc.cve_id
                WHERE sc.service_name LIKE ?
            '''
            params = [f'%{service_name}%']
            
            if include_lower_versions:
                query += ' AND sc.version <= ?'
            else:
                query += ' AND sc.version = ?'
            params.append(version)
            
        else:
            query = '''
                SELECT DISTINCT c.* FROM cves c
                JOIN service_cves sc ON c.cve_id = sc.cve_id
                WHERE sc.service_name LIKE ?
            '''
            params = [f'%{service_name}%']
            
        query += ' ORDER BY c.cvss_v3_score DESC'
        
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            results.append(_row_to_dict(row))
            
        # If no cached results, search NVD
        if not results:
            logger.info(f"No cached CVEs for {service_name}, searching NVD...")
            results = _search_nvd_by_cpe(service_name, version)
            for cve_data in results:
                _cache_cve(db, cve_data)
                _cache_service_mapping(db, service_name, version, cve_data['cve_id'])
                
        return results
        
    finally:
        db.close()


def get_cve_statistics(start_date: str = None, end_date: str = None) -> Dict[str, Any]:
    """
    Get CVE statistics for a date range.
    
    Args:
        start_date: Start date (ISO format)
        end_date: End date (ISO format)
        
    Returns:
        dict: Statistics including counts by severity
    """
    db = CVEDatabase()
    
    try:
        cursor = db.conn.cursor()
        
        # Base query
        query = 'SELECT severity, COUNT(*) as count FROM cves'
        params = []
        
        if start_date or end_date:
            conditions = []
            if start_date:
                conditions.append('published_date >= ?')
                params.append(start_date)
            if end_date:
                conditions.append('published_date <= ?')
                params.append(end_date)
            query += ' WHERE ' + ' AND '.join(conditions)
            
        query += ' GROUP BY severity'
        
        cursor.execute(query, params)
        
        stats = {
            'total': 0,
            'by_severity': {},
            'date_range': {
                'start': start_date,
                'end': end_date
            }
        }
        
        for row in cursor.fetchall():
            severity = row['severity'] or 'UNKNOWN'
            count = row['count']
            stats['by_severity'][severity] = count
            stats['total'] += count
            
        # Get average CVSS score
        cursor.execute('SELECT AVG(cvss_v3_score) as avg_score FROM cves WHERE cvss_v3_score IS NOT NULL')
        avg_row = cursor.fetchone()
        stats['average_cvss_score'] = round(avg_row['avg_score'], 2) if avg_row['avg_score'] else 0
        
        return stats
        
    finally:
        db.close()


def check_vulnerabilities_batch(services: List[Dict[str, str]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Check vulnerabilities for multiple services at once.
    
    Args:
        services: List of dicts with 'name' and 'version' keys
        
    Returns:
        dict: Mapping of service identifiers to their CVEs
        
    Example:
        >>> services = [
        >>>     {'name': 'Apache', 'version': '2.4.49'},
        >>>     {'name': 'OpenSSH', 'version': '7.4'}
        >>> ]
        >>> vulns = check_vulnerabilities_batch(services)
    """
    results = {}
    
    for service in services:
        service_key = f"{service['name']}:{service.get('version', 'unknown')}"
        cves = search_cves_by_service(service['name'], service.get('version'))
        results[service_key] = cves
        
    return results


def calculate_risk_score(cve_data: Dict[str, Any], 
                        asset_criticality: int = 5,
                        exposure_level: int = 5) -> Dict[str, Any]:
    """
    Calculate risk score for a CVE based on CVSS and environmental factors.
    
    Args:
        cve_data: CVE information including CVSS scores
        asset_criticality: Asset criticality (1-10)
        exposure_level: Exposure level (1-10)
        
    Returns:
        dict: Risk calculation results
    """
    cvss_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score', 0)
    
    # Calculate environmental score
    # Risk = CVSS * Asset Criticality * Exposure / 100
    raw_risk = (cvss_score * asset_criticality * exposure_level) / 100
    
    # Normalize to 0-10 scale
    risk_score = min(10, max(0, raw_risk))
    
    # Determine risk level
    if risk_score >= 9:
        risk_level = 'CRITICAL'
    elif risk_score >= 7:
        risk_level = 'HIGH'
    elif risk_score >= 4:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
        
    return {
        'cve_id': cve_data.get('cve_id'),
        'base_cvss': cvss_score,
        'asset_criticality': asset_criticality,
        'exposure_level': exposure_level,
        'risk_score': round(risk_score, 2),
        'risk_level': risk_level,
        'recommendation': _get_risk_recommendation(risk_level)
    }


def _get_risk_recommendation(risk_level: str) -> str:
    """Get recommendation based on risk level."""
    recommendations = {
        'CRITICAL': 'Patch immediately or implement compensating controls',
        'HIGH': 'Patch within 7 days or implement mitigations',
        'MEDIUM': 'Patch within 30 days during maintenance window',
        'LOW': 'Patch during next scheduled maintenance'
    }
    return recommendations.get(risk_level, 'Assess based on environment')


# Helper functions
def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert database row to dictionary."""
    result = dict(row)
    
    # Parse JSON fields
    if result.get('cve_references'):
        try:
            result['references'] = json.loads(result['cve_references'])
        except:
            result['references'] = []
            
    if result.get('cpe_matches'):
        try:
            result['cpe_matches'] = json.loads(result['cpe_matches'])
        except:
            result['cpe_matches'] = []
            
    if result.get('cwe_ids'):
        try:
            result['cwe_ids'] = json.loads(result['cwe_ids'])
        except:
            result['cwe_ids'] = []
            
    return result


def _cache_cve(db: CVEDatabase, cve_data: Dict[str, Any]):
    """Cache CVE data in database."""
    cursor = db.conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO cves (
            cve_id, description, cvss_v3_score, cvss_v3_vector,
            cvss_v2_score, cvss_v2_vector, severity,
            published_date, last_modified_date, cve_references,
            cpe_matches, cwe_ids, last_fetched
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        cve_data.get('cve_id'),
        cve_data.get('description'),
        cve_data.get('cvss_v3_score'),
        cve_data.get('cvss_v3_vector'),
        cve_data.get('cvss_v2_score'),
        cve_data.get('cvss_v2_vector'),
        cve_data.get('severity'),
        cve_data.get('published_date'),
        cve_data.get('last_modified_date'),
        json.dumps(cve_data.get('references', [])),
        json.dumps(cve_data.get('cpe_matches', [])),
        json.dumps(cve_data.get('cwe_ids', [])),
        datetime.now().isoformat()
    ))
    
    db.conn.commit()


def _cache_service_mapping(db: CVEDatabase, service_name: str, version: str, cve_id: str):
    """Cache service to CVE mapping."""
    cursor = db.conn.cursor()
    
    cursor.execute('''
        INSERT OR IGNORE INTO service_cves (service_name, version, cve_id)
        VALUES (?, ?, ?)
    ''', (service_name, version or '', cve_id))
    
    db.conn.commit()


def _fetch_cve_from_nvd(cve_id: str, api_key: str = None) -> Optional[Dict[str, Any]]:
    """
    Fetch CVE data from NVD API.
    
    Uses NVD API 2.0 to fetch real CVE data. Falls back to cached sample data
    if API is unavailable or rate limited.
    
    Args:
        cve_id: CVE identifier
        api_key: Optional NVD API key for higher rate limits
        
    Returns:
        CVE data dictionary or None
    """
    import urllib.request
    import urllib.parse
    import urllib.error
    import ssl
    import ssl
    import time
    
    # NVD API 2.0 endpoint
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'cveId': cve_id}
    
    # Add API key if provided (increases rate limit from 5 to 50 requests per 30 seconds)
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    try:
        # Build request URL
        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        
        # Create request with headers
        request = urllib.request.Request(url, headers=headers)
        
        # Create SSL context that doesn't verify certificates (for development)
        # In production, use proper certificate verification
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Make API call with timeout
        with urllib.request.urlopen(request, timeout=10, context=ssl_context) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                
                # Parse NVD response
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # Extract CVSS scores
                    cvss_v3_score = 0.0
                    cvss_v3_vector = ""
                    severity = "UNKNOWN"
                    
                    if 'metrics' in vuln:
                        if 'cvssMetricV31' in vuln['metrics']:
                            metric = vuln['metrics']['cvssMetricV31'][0]
                            cvss_v3_score = metric['cvssData']['baseScore']
                            cvss_v3_vector = metric['cvssData']['vectorString']
                            severity = metric['cvssData']['baseSeverity']
                        elif 'cvssMetricV30' in vuln['metrics']:
                            metric = vuln['metrics']['cvssMetricV30'][0]
                            cvss_v3_score = metric['cvssData']['baseScore']
                            cvss_v3_vector = metric['cvssData']['vectorString']
                            severity = metric['cvssData']['baseSeverity']
                    
                    # Extract description
                    description = ""
                    if 'descriptions' in vuln:
                        for desc in vuln['descriptions']:
                            if desc['lang'] == 'en':
                                description = desc['value']
                                break
                    
                    # Extract references
                    references = []
                    if 'references' in vuln:
                        references = [ref['url'] for ref in vuln['references']]
                    
                    # Extract CPE matches
                    cpe_matches = []
                    if 'configurations' in vuln:
                        for config in vuln['configurations']:
                            if 'nodes' in config:
                                for node in config['nodes']:
                                    if 'cpeMatch' in node:
                                        for match in node['cpeMatch']:
                                            if 'criteria' in match:
                                                cpe_matches.append(match['criteria'])
                    
                    # Extract CWE IDs
                    cwe_ids = []
                    if 'weaknesses' in vuln:
                        for weakness in vuln['weaknesses']:
                            if 'description' in weakness:
                                for desc in weakness['description']:
                                    if desc['lang'] == 'en' and desc['value'].startswith('CWE-'):
                                        cwe_ids.append(desc['value'])
                    
                    return {
                        'cve_id': vuln['id'],
                        'description': description,
                        'cvss_v3_score': cvss_v3_score,
                        'cvss_v3_vector': cvss_v3_vector,
                        'severity': severity,
                        'published_date': vuln.get('published', ''),
                        'last_modified_date': vuln.get('lastModified', ''),
                        'references': references[:10],  # Limit references
                        'cpe_matches': cpe_matches[:10],  # Limit CPE matches
                        'cwe_ids': cwe_ids
                    }
                    
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logger.warning(f"NVD API rate limit exceeded for {cve_id}")
        else:
            logger.error(f"NVD API HTTP error {e.code} for {cve_id}: {e.reason}")
    except urllib.error.URLError as e:
        logger.error(f"NVD API connection error for {cve_id}: {e.reason}")
    except Exception as e:
        logger.error(f"Error fetching CVE {cve_id} from NVD: {str(e)}")
    
    # Fallback to sample data for common CVEs
    sample_cves = {
        'CVE-2021-44228': {
            'cve_id': 'CVE-2021-44228',
            'description': 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.',
            'cvss_v3_score': 10.0,
            'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'severity': 'CRITICAL',
            'published_date': '2021-12-10',
            'last_modified_date': '2021-12-14',
            'references': [
                'https://logging.apache.org/log4j/2.x/security.html',
                'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
            ],
            'cpe_matches': ['cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'],
            'cwe_ids': ['CWE-502', 'CWE-400']
        },
        'CVE-2014-0160': {
            'cve_id': 'CVE-2014-0160',
            'description': 'The TLS and DTLS implementations in OpenSSL do not properly handle Heartbeat Extension packets (Heartbleed).',
            'cvss_v3_score': 7.5,
            'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'severity': 'HIGH',
            'published_date': '2014-04-07',
            'last_modified_date': '2020-10-15',
            'references': [
                'http://heartbleed.com/',
                'https://nvd.nist.gov/vuln/detail/CVE-2014-0160'
            ],
            'cpe_matches': ['cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*'],
            'cwe_ids': ['CWE-126']
        }
    }
    
    return sample_cves.get(cve_id)


def _search_nvd_by_keyword(keyword: str, limit: int = 50, api_key: str = None) -> List[Dict[str, Any]]:
    """
    Search NVD by keyword using NVD API 2.0.
    
    Args:
        keyword: Search keyword
        limit: Maximum results to return
        api_key: Optional NVD API key
        
    Returns:
        List of CVE data dictionaries
    """
    import urllib.request
    import urllib.parse
    import urllib.error
    import ssl
    
    # NVD API 2.0 search endpoint
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': min(limit, 100)  # API max is 2000 but we'll be conservative
    }
    
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    results = []
    
    try:
        # Build request URL
        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        
        # Create request
        request = urllib.request.Request(url, headers=headers)
        
        # Create SSL context (same as above)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Make API call
        with urllib.request.urlopen(request, timeout=15, context=ssl_context) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                
                # Parse vulnerabilities
                for vuln_wrapper in data.get('vulnerabilities', [])[:limit]:
                    vuln = vuln_wrapper['cve']
                    
                    # Extract basic info
                    cve_data = {
                        'cve_id': vuln['id'],
                        'description': '',
                        'cvss_v3_score': 0.0,
                        'severity': 'UNKNOWN',
                        'published_date': vuln.get('published', ''),
                        'last_modified_date': vuln.get('lastModified', '')
                    }
                    
                    # Get description
                    if 'descriptions' in vuln:
                        for desc in vuln['descriptions']:
                            if desc['lang'] == 'en':
                                cve_data['description'] = desc['value'][:500]  # Limit length
                                break
                    
                    # Get CVSS score
                    if 'metrics' in vuln:
                        if 'cvssMetricV31' in vuln['metrics']:
                            metric = vuln['metrics']['cvssMetricV31'][0]
                            cve_data['cvss_v3_score'] = metric['cvssData']['baseScore']
                            cve_data['severity'] = metric['cvssData']['baseSeverity']
                        elif 'cvssMetricV30' in vuln['metrics']:
                            metric = vuln['metrics']['cvssMetricV30'][0]
                            cve_data['cvss_v3_score'] = metric['cvssData']['baseScore']
                            cve_data['severity'] = metric['cvssData']['baseSeverity']
                    
                    results.append(cve_data)
                    
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logger.warning(f"NVD API rate limit exceeded for search '{keyword}'")
        else:
            logger.error(f"NVD API HTTP error {e.code} for search '{keyword}': {e.reason}")
    except Exception as e:
        logger.error(f"Error searching NVD for '{keyword}': {str(e)}")
    
    # If no results from API, try sample data as fallback
    if not results:
        if 'log4j' in keyword.lower():
            cve = _fetch_cve_from_nvd('CVE-2021-44228')
            if cve:
                results.append(cve)
                
        if 'heartbleed' in keyword.lower() or 'openssl' in keyword.lower():
            cve = _fetch_cve_from_nvd('CVE-2014-0160')
            if cve:
                results.append(cve)
    
    return results[:limit]


def _search_nvd_by_cpe(product: str, version: str = None) -> List[Dict[str, Any]]:
    """Search NVD by CPE (Common Platform Enumeration)."""
    # Simulated search - in production, use NVD API
    results = []
    
    if 'apache' in product.lower():
        cve = _fetch_cve_from_nvd('CVE-2021-44228')
        if cve:
            results.append(cve)
            
    if 'openssl' in product.lower():
        cve = _fetch_cve_from_nvd('CVE-2014-0160')
        if cve:
            results.append(cve)
            
    return results


# Sync functions for updating local database
def sync_nvd_feed(year: int = None, api_key: str = None, max_results: int = 100) -> Dict[str, Any]:
    """
    Sync CVE data from NVD feeds using NVD API 2.0.
    
    This function fetches recent CVEs and stores them in the local database.
    Note: Without an API key, you're limited to 5 requests per 30 seconds.
    With an API key, the limit increases to 50 requests per 30 seconds.
    
    Args:
        year: Year to sync (default: current year)
        api_key: NVD API key (recommended for higher rate limits)
        max_results: Maximum CVEs to sync (default: 100)
        
    Returns:
        dict: Sync statistics
    """
    import urllib.request
    import urllib.parse
    import urllib.error
    import ssl
    from datetime import datetime, timedelta
    
    if year is None:
        year = datetime.now().year
        
    stats = {
        'year': year,
        'total_processed': 0,
        'new_cves': 0,
        'updated_cves': 0,
        'errors': 0,
        'start_time': datetime.now().isoformat()
    }
    
    # Create database instance
    db = CVEDatabase()
    
    # NVD API endpoint
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Set date range for the year
    start_date = f"{year}-01-01T00:00:00.000"
    end_date = f"{year}-12-31T23:59:59.999"
    
    params = {
        'pubStartDate': start_date,
        'pubEndDate': end_date,
        'resultsPerPage': min(max_results, 100)
    }
    
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    
    logger.info(f"Syncing NVD feed for year {year}")
    
    try:
        # Build request URL
        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        
        # Create request
        request = urllib.request.Request(url, headers=headers)
        
        # Create SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Make API call
        with urllib.request.urlopen(request, timeout=30, context=ssl_context) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                
                total_results = data.get('totalResults', 0)
                logger.info(f"Found {total_results} CVEs for year {year}")
                
                # Process vulnerabilities
                for vuln_wrapper in data.get('vulnerabilities', []):
                    try:
                        vuln = vuln_wrapper['cve']
                        cve_id = vuln['id']
                        
                        # Check if already exists
                        existing = db.get_cve(cve_id)
                        
                        # Extract CVE data
                        cve_data = {
                            'cve_id': cve_id,
                            'description': '',
                            'cvss_v3_score': 0.0,
                            'cvss_v3_vector': '',
                            'severity': 'UNKNOWN',
                            'published_date': vuln.get('published', ''),
                            'last_modified_date': vuln.get('lastModified', ''),
                            'references': [],
                            'cpe_matches': [],
                            'cwe_ids': []
                        }
                        
                        # Get description
                        if 'descriptions' in vuln:
                            for desc in vuln['descriptions']:
                                if desc['lang'] == 'en':
                                    cve_data['description'] = desc['value']
                                    break
                        
                        # Get CVSS metrics
                        if 'metrics' in vuln:
                            if 'cvssMetricV31' in vuln['metrics']:
                                metric = vuln['metrics']['cvssMetricV31'][0]
                                cve_data['cvss_v3_score'] = metric['cvssData']['baseScore']
                                cve_data['cvss_v3_vector'] = metric['cvssData']['vectorString']
                                cve_data['severity'] = metric['cvssData']['baseSeverity']
                            elif 'cvssMetricV30' in vuln['metrics']:
                                metric = vuln['metrics']['cvssMetricV30'][0]
                                cve_data['cvss_v3_score'] = metric['cvssData']['baseScore']
                                cve_data['cvss_v3_vector'] = metric['cvssData']['vectorString']
                                cve_data['severity'] = metric['cvssData']['baseSeverity']
                        
                        # Get references (limit to 5)
                        if 'references' in vuln:
                            cve_data['references'] = [ref['url'] for ref in vuln['references'][:5]]
                        
                        # Store in database
                        _store_cve_in_db(db, cve_data)
                        
                        if existing:
                            stats['updated_cves'] += 1
                        else:
                            stats['new_cves'] += 1
                            
                        stats['total_processed'] += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing CVE {cve_id}: {str(e)}")
                        stats['errors'] += 1
                        
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logger.error("NVD API rate limit exceeded. Consider using an API key or reducing request frequency.")
        else:
            logger.error(f"NVD API HTTP error {e.code}: {e.reason}")
        stats['errors'] += 1
    except Exception as e:
        logger.error(f"Error syncing NVD feed: {str(e)}")
        stats['errors'] += 1
    
    stats['end_time'] = datetime.now().isoformat()
    
    # Log summary
    logger.info(f"Sync completed: {stats['new_cves']} new, {stats['updated_cves']} updated, {stats['errors']} errors")
    
    return stats