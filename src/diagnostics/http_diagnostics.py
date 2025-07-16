#!/usr/bin/env python3
"""
SuperSleuth Network - HTTP/HTTPS Diagnostics Module
Provides comprehensive HTTP/HTTPS endpoint monitoring and diagnostics capabilities.
"""

import http.client
import ssl
import socket
import time
import json
import base64
from urllib.parse import urlparse, urlencode
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any


def test_http_endpoint(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    verify_ssl: bool = True,
    expected_status: Optional[int] = None,
    expected_content: Optional[str] = None,
    auth: Optional[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Test an HTTP/HTTPS endpoint with comprehensive diagnostics.
    
    Args:
        url: The URL to test
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Optional headers to include
        body: Optional request body
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        max_redirects: Maximum number of redirects to follow
        verify_ssl: Whether to verify SSL certificates
        expected_status: Expected HTTP status code
        expected_content: Expected content in response
        auth: Optional (username, password) tuple for basic auth
        
    Returns:
        Dictionary containing test results and diagnostics
    """
    result = {
        'url': url,
        'method': method,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'success': False,
        'error': None,
        'response': None,
        'timing': {},
        'redirects': [],
        'ssl_info': None
    }
    
    try:
        # Parse URL
        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'
        host = parsed.hostname or 'localhost'
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
            
        # Prepare headers
        if headers is None:
            headers = {}
        headers['Host'] = host
        headers['User-Agent'] = headers.get('User-Agent', 'SuperSleuth-Network/1.0')
        
        # Add basic auth if provided
        if auth:
            credentials = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            headers['Authorization'] = f'Basic {credentials}'
            
        # Track redirects
        redirect_count = 0
        current_url = url
        
        while redirect_count <= max_redirects:
            # Parse current URL
            parsed = urlparse(current_url)
            is_https = parsed.scheme == 'https'
            host = parsed.hostname or 'localhost'
            port = parsed.port or (443 if is_https else 80)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
                
            # Create connection
            start_time = time.time()
            
            if is_https:
                # Create SSL context
                context = ssl.create_default_context()
                if not verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                conn = http.client.HTTPSConnection(
                    host, port, timeout=timeout, context=context
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                
            try:
                # Connect
                connect_start = time.time()
                conn.connect()
                connect_time = time.time() - connect_start
                
                # Get SSL info if HTTPS
                if is_https and hasattr(conn.sock, 'getpeercert'):
                    result['ssl_info'] = _get_ssl_info(conn.sock)
                    
                # Send request
                request_start = time.time()
                conn.request(method, path, body, headers)
                
                # Get response
                response = conn.getresponse()
                response_time = time.time() - request_start
                
                # Read response data
                response_data = response.read()
                total_time = time.time() - start_time
                
                # Record timing
                timing = {
                    'connect_time': round(connect_time * 1000, 2),
                    'response_time': round(response_time * 1000, 2),
                    'total_time': round(total_time * 1000, 2)
                }
                
                # Build response info
                response_info = {
                    'status_code': response.status,
                    'status_reason': response.reason,
                    'headers': dict(response.headers),
                    'body': response_data.decode('utf-8', errors='replace'),
                    'body_size': len(response_data),
                    'timing': timing
                }
                
                # Check for redirect
                if response.status in (301, 302, 303, 307, 308) and follow_redirects:
                    location = response.getheader('Location')
                    if location:
                        # Record redirect
                        result['redirects'].append({
                            'from': current_url,
                            'to': location,
                            'status': response.status
                        })
                        
                        # Update current URL
                        if location.startswith('http'):
                            current_url = location
                        else:
                            # Relative redirect
                            base = f"{parsed.scheme}://{host}"
                            if port not in (80, 443):
                                base += f":{port}"
                            current_url = base + location
                            
                        redirect_count += 1
                        continue
                        
                # Final response
                result['response'] = response_info
                result['timing'] = timing
                
                # Check expected status
                if expected_status:
                    if response.status != expected_status:
                        result['error'] = f"Expected status {expected_status}, got {response.status}"
                    else:
                        result['success'] = True
                else:
                    result['success'] = response.status < 400
                    
                # Check expected content
                if expected_content and expected_content not in response_data.decode('utf-8', errors='replace'):
                    result['error'] = f"Expected content not found: {expected_content}"
                    result['success'] = False
                    
                break
                
            finally:
                conn.close()
                
        if redirect_count > max_redirects:
            result['error'] = f"Too many redirects (>{max_redirects})"
            
    except socket.timeout:
        result['error'] = f"Connection timeout after {timeout}s"
    except ssl.SSLError as e:
        result['error'] = f"SSL error: {str(e)}"
    except Exception as e:
        result['error'] = f"Error: {type(e).__name__}: {str(e)}"
        
    return result


def test_response_time(
    url: str,
    threshold_ms: float = 1000.0,
    samples: int = 3,
    method: str = 'GET',
    **kwargs
) -> Dict[str, Any]:
    """
    Test response time of an endpoint with multiple samples.
    
    Args:
        url: The URL to test
        threshold_ms: Response time threshold in milliseconds
        samples: Number of samples to take
        method: HTTP method
        **kwargs: Additional arguments for test_http_endpoint
        
    Returns:
        Dictionary with response time analysis
    """
    result = {
        'url': url,
        'threshold_ms': threshold_ms,
        'samples': samples,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'success': False,
        'measurements': [],
        'statistics': {}
    }
    
    times = []
    errors = []
    
    for i in range(samples):
        test_result = test_http_endpoint(url, method=method, **kwargs)
        
        if test_result['success'] and test_result['response']:
            response_time = test_result['response']['timing']['total_time']
            times.append(response_time)
            result['measurements'].append({
                'sample': i + 1,
                'response_time_ms': response_time,
                'status_code': test_result['response']['status_code']
            })
        else:
            errors.append(test_result['error'])
            result['measurements'].append({
                'sample': i + 1,
                'error': test_result['error']
            })
            
        # Small delay between samples
        if i < samples - 1:
            time.sleep(0.5)
            
    if times:
        # Calculate statistics
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        result['statistics'] = {
            'avg_response_time_ms': round(avg_time, 2),
            'min_response_time_ms': round(min_time, 2),
            'max_response_time_ms': round(max_time, 2),
            'successful_samples': len(times),
            'failed_samples': len(errors)
        }
        
        # Check threshold
        result['success'] = avg_time <= threshold_ms
        if not result['success']:
            result['error'] = f"Average response time ({avg_time:.2f}ms) exceeds threshold ({threshold_ms}ms)"
    else:
        result['error'] = "All samples failed"
        
    return result


def validate_ssl_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 10.0
) -> Dict[str, Any]:
    """
    Validate SSL/TLS certificate for a hostname.
    
    Args:
        hostname: The hostname to check
        port: The port number (default 443)
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary with SSL certificate validation results
    """
    result = {
        'hostname': hostname,
        'port': port,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'valid': False,
        'error': None,
        'certificate': None,
        'warnings': []
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    # Parse certificate info
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': []
                    }
                    
                    # Get Subject Alternative Names
                    for ext in cert.get('subjectAltName', []):
                        if ext[0] == 'DNS':
                            cert_info['san'].append(ext[1])
                            
                    result['certificate'] = cert_info
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    
                    if now > not_after:
                        result['warnings'].append('Certificate has expired')
                    elif (not_after - now).days < 30:
                        result['warnings'].append(f'Certificate expires in {(not_after - now).days} days')
                        
                    # Check hostname match
                    ssl.match_hostname(cert, hostname)
                    
                    result['valid'] = True
                    
    except ssl.CertificateError as e:
        result['error'] = f"Certificate validation failed: {str(e)}"
    except socket.timeout:
        result['error'] = f"Connection timeout after {timeout}s"
    except Exception as e:
        result['error'] = f"Error: {type(e).__name__}: {str(e)}"
        
    return result


def analyze_http_headers(
    url: str,
    security_headers: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """
    Analyze HTTP headers from a response.
    
    Args:
        url: The URL to test
        security_headers: Whether to check for security headers
        **kwargs: Additional arguments for test_http_endpoint
        
    Returns:
        Dictionary with header analysis
    """
    result = {
        'url': url,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'headers': {},
        'security_analysis': {},
        'warnings': [],
        'recommendations': []
    }
    
    # Get response
    test_result = test_http_endpoint(url, **kwargs)
    
    if not test_result['success'] or not test_result['response']:
        result['error'] = test_result['error'] or "Failed to get response"
        return result
        
    headers = test_result['response']['headers']
    result['headers'] = headers
    
    # Analyze security headers if requested
    if security_headers:
        security_headers_check = {
            'Strict-Transport-Security': {
                'present': False,
                'recommendation': 'Add HSTS header for HTTPS connections'
            },
            'X-Content-Type-Options': {
                'present': False,
                'expected': 'nosniff',
                'recommendation': 'Add X-Content-Type-Options: nosniff'
            },
            'X-Frame-Options': {
                'present': False,
                'expected': ['DENY', 'SAMEORIGIN'],
                'recommendation': 'Add X-Frame-Options to prevent clickjacking'
            },
            'Content-Security-Policy': {
                'present': False,
                'recommendation': 'Add Content-Security-Policy header'
            },
            'X-XSS-Protection': {
                'present': False,
                'expected': '1; mode=block',
                'recommendation': 'Add X-XSS-Protection header'
            }
        }
        
        # Check each security header
        for header, check in security_headers_check.items():
            if header in headers:
                check['present'] = True
                check['value'] = headers[header]
                
                # Validate expected values
                if 'expected' in check:
                    if isinstance(check['expected'], list):
                        if headers[header] not in check['expected']:
                            result['warnings'].append(
                                f"{header} has unexpected value: {headers[header]}"
                            )
                    elif headers[header] != check['expected']:
                        result['warnings'].append(
                            f"{header} should be '{check['expected']}', got '{headers[header]}'"
                        )
            else:
                result['recommendations'].append(check['recommendation'])
                
        result['security_analysis'] = security_headers_check
        
    # Check for other important headers
    if 'Server' in headers:
        result['warnings'].append(f"Server header exposes version: {headers['Server']}")
        
    if 'Set-Cookie' in headers and 'Secure' not in headers.get('Set-Cookie', ''):
        if urlparse(url).scheme == 'https':
            result['warnings'].append("Cookie set without Secure flag on HTTPS")
            
    return result


def test_authentication(
    url: str,
    auth_type: str = 'basic',
    credentials: Optional[Dict[str, str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Test authentication for an endpoint.
    
    Args:
        url: The URL to test
        auth_type: Type of authentication (basic, bearer, custom)
        credentials: Authentication credentials
        **kwargs: Additional arguments for test_http_endpoint
        
    Returns:
        Dictionary with authentication test results
    """
    result = {
        'url': url,
        'auth_type': auth_type,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'authenticated': False,
        'tests': []
    }
    
    # Test without authentication
    no_auth_test = test_http_endpoint(url, **kwargs)
    result['tests'].append({
        'name': 'No authentication',
        'status_code': no_auth_test['response']['status_code'] if no_auth_test['response'] else None,
        'success': no_auth_test['success'],
        'error': no_auth_test['error']
    })
    
    # Test with authentication
    if credentials:
        if auth_type == 'basic':
            auth = (credentials.get('username'), credentials.get('password'))
            auth_test = test_http_endpoint(url, auth=auth, **kwargs)
        elif auth_type == 'bearer':
            headers = kwargs.get('headers', {})
            headers['Authorization'] = f"Bearer {credentials.get('token')}"
            kwargs['headers'] = headers
            auth_test = test_http_endpoint(url, **kwargs)
        else:
            # Custom headers
            headers = kwargs.get('headers', {})
            headers.update(credentials)
            kwargs['headers'] = headers
            auth_test = test_http_endpoint(url, **kwargs)
            
        result['tests'].append({
            'name': f'{auth_type} authentication',
            'status_code': auth_test['response']['status_code'] if auth_test['response'] else None,
            'success': auth_test['success'],
            'error': auth_test['error']
        })
        
        if auth_test['success'] and auth_test['response']['status_code'] < 400:
            result['authenticated'] = True
            
    return result


def test_api_endpoint(
    url: str,
    method: str = 'GET',
    json_data: Optional[Dict] = None,
    expected_json_schema: Optional[Dict] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Test an API endpoint with JSON validation.
    
    Args:
        url: The API endpoint URL
        method: HTTP method
        json_data: JSON data to send
        expected_json_schema: Expected JSON response structure
        **kwargs: Additional arguments for test_http_endpoint
        
    Returns:
        Dictionary with API test results
    """
    result = {
        'url': url,
        'method': method,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'success': False,
        'json_valid': False,
        'schema_valid': False
    }
    
    # Prepare headers for JSON
    headers = kwargs.get('headers', {})
    headers['Content-Type'] = 'application/json'
    headers['Accept'] = 'application/json'
    kwargs['headers'] = headers
    
    # Convert JSON data to string
    body = None
    if json_data:
        body = json.dumps(json_data)
        
    # Make request
    test_result = test_http_endpoint(url, method=method, body=body, **kwargs)
    result.update(test_result)
    
    if test_result['success'] and test_result['response']:
        # Try to parse JSON response
        try:
            response_json = json.loads(test_result['response']['body'])
            result['json_valid'] = True
            result['json_response'] = response_json
            
            # Validate schema if provided
            if expected_json_schema:
                result['schema_valid'] = _validate_json_schema(
                    response_json, expected_json_schema
                )
                
        except json.JSONDecodeError as e:
            result['json_error'] = f"Invalid JSON: {str(e)}"
            
    return result


def _get_ssl_info(sock) -> Dict[str, Any]:
    """Get SSL certificate information from a socket."""
    cert = sock.getpeercert()
    cipher = sock.cipher()
    
    info = {
        'protocol': sock.version(),
        'cipher': {
            'name': cipher[0] if cipher else None,
            'version': cipher[1] if cipher and len(cipher) > 1 else None,
            'bits': cipher[2] if cipher and len(cipher) > 2 else None
        }
    }
    
    if cert:
        info['certificate'] = {
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert.get('version'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter')
        }
        
    return info


def _validate_json_schema(data: Any, schema: Dict) -> bool:
    """Basic JSON schema validation."""
    if isinstance(schema, dict):
        if not isinstance(data, dict):
            return False
        for key, expected_type in schema.items():
            if key not in data:
                return False
            if not _validate_json_schema(data[key], expected_type):
                return False
    elif isinstance(schema, list):
        if not isinstance(data, list):
            return False
        if schema:  # Non-empty schema list
            for item in data:
                if not _validate_json_schema(item, schema[0]):
                    return False
    elif isinstance(schema, type):
        return isinstance(data, schema)
    elif schema is not None:
        return data == schema
        
    return True


def diagnose_web_issue(url: str, verbose: bool = True) -> Dict[str, Any]:
    """
    Comprehensive web diagnostics for common issues.
    
    Args:
        url: The URL to diagnose
        verbose: Whether to include detailed diagnostics
        
    Returns:
        Dictionary with comprehensive diagnostics and recommendations
    """
    result = {
        'url': url,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'issues': [],
        'recommendations': [],
        'diagnostics': {}
    }
    
    # Basic connectivity test
    basic_test = test_http_endpoint(url, timeout=30.0)
    result['diagnostics']['basic_connectivity'] = basic_test
    
    if not basic_test['success']:
        result['issues'].append(f"Cannot reach {url}: {basic_test['error']}")
        
        # Check if it's an SSL issue
        if 'SSL' in str(basic_test['error']):
            result['recommendations'].append("Try with verify_ssl=False to bypass certificate validation")
            result['recommendations'].append("Check SSL certificate validity")
            
            # Try without SSL verification
            no_ssl_test = test_http_endpoint(url, verify_ssl=False)
            if no_ssl_test['success']:
                result['issues'].append("SSL certificate validation is failing")
                result['diagnostics']['without_ssl_verification'] = no_ssl_test
                
        return result
        
    # Response time analysis
    if verbose:
        response_time_test = test_response_time(url, threshold_ms=3000, samples=3)
        result['diagnostics']['response_time'] = response_time_test
        
        if not response_time_test['success']:
            result['issues'].append("Slow response times detected")
            result['recommendations'].append("Check server load and network latency")
            
    # SSL certificate check for HTTPS
    parsed = urlparse(url)
    if parsed.scheme == 'https':
        ssl_test = validate_ssl_certificate(parsed.hostname, parsed.port or 443)
        result['diagnostics']['ssl_certificate'] = ssl_test
        
        if not ssl_test['valid']:
            result['issues'].append(f"SSL certificate issue: {ssl_test['error']}")
            
        if ssl_test['warnings']:
            result['issues'].extend(ssl_test['warnings'])
            
    # Header analysis
    header_analysis = analyze_http_headers(url)
    result['diagnostics']['headers'] = header_analysis
    
    if header_analysis['warnings']:
        result['issues'].extend(header_analysis['warnings'])
        
    if header_analysis['recommendations']:
        result['recommendations'].extend(header_analysis['recommendations'])
        
    # Check for common issues
    if basic_test['response']:
        status_code = basic_test['response']['status_code']
        
        if status_code >= 500:
            result['issues'].append(f"Server error: {status_code}")
            result['recommendations'].append("Check server logs for errors")
        elif status_code >= 400:
            if status_code == 401:
                result['issues'].append("Authentication required")
                result['recommendations'].append("Provide valid credentials")
            elif status_code == 403:
                result['issues'].append("Access forbidden")
                result['recommendations'].append("Check permissions and access controls")
            elif status_code == 404:
                result['issues'].append("Resource not found")
                result['recommendations'].append("Verify the URL is correct")
                
    # Check redirects
    if basic_test['redirects']:
        result['issues'].append(f"Multiple redirects detected ({len(basic_test['redirects'])})")
        for redirect in basic_test['redirects']:
            result['recommendations'].append(
                f"Redirect: {redirect['from']} -> {redirect['to']} ({redirect['status']})"
            )
            
    return result


if __name__ == '__main__':
    # Example usage
    print("SuperSleuth Network - HTTP Diagnostics Module")
    print("=" * 50)
    
    # Test a website
    url = "https://example.com"
    print(f"\nTesting {url}...")
    
    result = diagnose_web_issue(url)
    print(f"\nIssues found: {len(result['issues'])}")
    for issue in result['issues']:
        print(f"  - {issue}")
        
    print(f"\nRecommendations: {len(result['recommendations'])}")
    for rec in result['recommendations']:
        print(f"  - {rec}")