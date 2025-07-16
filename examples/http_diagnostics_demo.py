#!/usr/bin/env python3
"""
SuperSleuth Network - HTTP Diagnostics Demo
Demonstrates how Claude Code would use the HTTP diagnostics tools for common scenarios.
"""

import sys
import json
import time
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, '../src')
from diagnostics.http_diagnostics import (
    test_http_endpoint,
    test_response_time,
    validate_ssl_certificate,
    analyze_http_headers,
    test_authentication,
    test_api_endpoint,
    diagnose_web_issue
)


def format_result(result: dict, indent: int = 2) -> str:
    """Format a result dictionary for display."""
    return json.dumps(result, indent=indent, default=str)


def demo_slow_website():
    """Demo: Diagnose a slow website."""
    print("\n" + "="*60)
    print("SCENARIO: 'Website is slow'")
    print("="*60)
    
    # Test with a public website
    url = "https://httpbin.org/delay/2"
    
    print(f"\nTesting response time for: {url}")
    print("Expected: This endpoint intentionally delays for 2 seconds")
    
    # Test response time with threshold
    result = test_response_time(
        url,
        threshold_ms=1000,  # 1 second threshold
        samples=3
    )
    
    print("\nResponse Time Analysis:")
    print(f"  Threshold: {result['threshold_ms']}ms")
    print(f"  Success: {result['success']}")
    
    if result['statistics']:
        stats = result['statistics']
        print(f"\nStatistics:")
        print(f"  Average: {stats['avg_response_time_ms']}ms")
        print(f"  Min: {stats['min_response_time_ms']}ms")
        print(f"  Max: {stats['max_response_time_ms']}ms")
        
    if not result['success']:
        print(f"\n⚠️  Issue: {result.get('error', 'Response time exceeds threshold')}")
        print("\nRecommendations:")
        print("  - Check server load and resources")
        print("  - Analyze network latency")
        print("  - Consider CDN or caching")
        print("  - Optimize backend processing")


def demo_api_errors():
    """Demo: Diagnose API errors."""
    print("\n" + "="*60)
    print("SCENARIO: 'API is returning errors'")
    print("="*60)
    
    # Test various API error scenarios
    test_cases = [
        {
            'url': 'https://httpbin.org/status/500',
            'description': 'Server Error (500)'
        },
        {
            'url': 'https://httpbin.org/status/404',
            'description': 'Not Found (404)'
        },
        {
            'url': 'https://httpbin.org/status/401',
            'description': 'Unauthorized (401)'
        }
    ]
    
    for test in test_cases:
        print(f"\nTesting: {test['description']}")
        print(f"URL: {test['url']}")
        
        result = test_http_endpoint(test['url'])
        
        if result['response']:
            status = result['response']['status_code']
            print(f"  Status: {status} {result['response']['status_reason']}")
            
            # Provide specific recommendations
            if status >= 500:
                print("  ⚠️  Server Error Detected")
                print("  Recommendations:")
                print("    - Check server logs for errors")
                print("    - Verify database connectivity")
                print("    - Check for unhandled exceptions")
            elif status == 404:
                print("  ⚠️  Resource Not Found")
                print("  Recommendations:")
                print("    - Verify the API endpoint URL")
                print("    - Check API documentation")
                print("    - Ensure resource exists")
            elif status == 401:
                print("  ⚠️  Authentication Required")
                print("  Recommendations:")
                print("    - Provide valid credentials")
                print("    - Check authentication token")
                print("    - Verify API key")


def demo_ssl_certificate():
    """Demo: Check SSL certificate issues."""
    print("\n" + "="*60)
    print("SCENARIO: 'SSL certificate warnings'")
    print("="*60)
    
    # Test SSL certificates
    test_sites = [
        {
            'hostname': 'example.com',
            'description': 'Valid certificate'
        },
        {
            'hostname': 'expired.badssl.com',
            'description': 'Expired certificate'
        },
        {
            'hostname': 'self-signed.badssl.com',
            'description': 'Self-signed certificate'
        }
    ]
    
    for site in test_sites:
        print(f"\nChecking: {site['description']}")
        print(f"Hostname: {site['hostname']}")
        
        result = validate_ssl_certificate(site['hostname'])
        
        print(f"  Valid: {result['valid']}")
        
        if result['certificate']:
            cert = result['certificate']
            print(f"  Issuer: {cert['issuer'].get('organizationName', 'Unknown')}")
            print(f"  Expires: {cert['not_after']}")
            
        if result['error']:
            print(f"  ⚠️  Error: {result['error']}")
            
        if result['warnings']:
            print("  ⚠️  Warnings:")
            for warning in result['warnings']:
                print(f"    - {warning}")
                
        if not result['valid']:
            print("  Recommendations:")
            print("    - Update SSL certificate")
            print("    - Use a trusted Certificate Authority")
            print("    - Check certificate expiration")


def demo_web_access():
    """Demo: Diagnose web application access issues."""
    print("\n" + "="*60)
    print("SCENARIO: 'Can't access web application'")
    print("="*60)
    
    # Comprehensive diagnosis
    url = "https://httpbin.org"
    
    print(f"\nRunning comprehensive diagnostics for: {url}")
    
    result = diagnose_web_issue(url, verbose=True)
    
    print(f"\nDiagnostics Summary:")
    print(f"  Issues found: {len(result['issues'])}")
    print(f"  Recommendations: {len(result['recommendations'])}")
    
    if result['issues']:
        print("\n⚠️  Issues:")
        for issue in result['issues']:
            print(f"  - {issue}")
            
    if result['recommendations']:
        print("\nRecommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
            
    # Show specific diagnostics
    if 'basic_connectivity' in result['diagnostics']:
        basic = result['diagnostics']['basic_connectivity']
        if basic['success']:
            print(f"\n✓ Basic connectivity: OK")
            if basic['response']:
                print(f"  Response time: {basic['response']['timing']['total_time']}ms")
        else:
            print(f"\n✗ Basic connectivity: FAILED")
            print(f"  Error: {basic['error']}")


def demo_authentication():
    """Demo: Test authentication issues."""
    print("\n" + "="*60)
    print("SCENARIO: 'Authentication issues'")
    print("="*60)
    
    # Test basic authentication
    url = "https://httpbin.org/basic-auth/user/passwd"
    
    print(f"\nTesting authentication for: {url}")
    
    # Test without credentials
    print("\n1. Testing without credentials:")
    result = test_authentication(url, auth_type='basic')
    
    for test in result['tests']:
        print(f"  {test['name']}: Status {test['status_code']}")
        
    # Test with wrong credentials
    print("\n2. Testing with wrong credentials:")
    wrong_creds = {'username': 'wrong', 'password': 'wrong'}
    result = test_authentication(url, auth_type='basic', credentials=wrong_creds)
    
    for test in result['tests']:
        if test['name'] != 'No authentication':
            print(f"  {test['name']}: Status {test['status_code']}")
            
    # Test with correct credentials
    print("\n3. Testing with correct credentials:")
    correct_creds = {'username': 'user', 'password': 'passwd'}
    result = test_authentication(url, auth_type='basic', credentials=correct_creds)
    
    for test in result['tests']:
        if test['name'] != 'No authentication':
            print(f"  {test['name']}: Status {test['status_code']}")
            
    print(f"\n✓ Authenticated: {result['authenticated']}")
    
    if not result['authenticated']:
        print("\nRecommendations:")
        print("  - Verify credentials are correct")
        print("  - Check authentication method (Basic, Bearer, etc.)")
        print("  - Ensure account is active")
        print("  - Check for IP restrictions")


def demo_api_validation():
    """Demo: Test API endpoint with JSON validation."""
    print("\n" + "="*60)
    print("SCENARIO: 'API JSON Response Validation'")
    print("="*60)
    
    # Test API endpoint
    url = "https://httpbin.org/json"
    
    print(f"\nTesting API endpoint: {url}")
    
    # Define expected schema
    expected_schema = {
        'slideshow': dict,
        'slideshow': {
            'author': str,
            'date': str,
            'title': str
        }
    }
    
    result = test_api_endpoint(
        url,
        expected_json_schema=expected_schema
    )
    
    print(f"\nAPI Test Results:")
    print(f"  HTTP Success: {result['success']}")
    print(f"  Valid JSON: {result['json_valid']}")
    print(f"  Schema Valid: {result['schema_valid']}")
    
    if result['json_valid'] and 'json_response' in result:
        print(f"\nJSON Response Preview:")
        preview = json.dumps(result['json_response'], indent=2)
        lines = preview.split('\n')
        for line in lines[:10]:  # Show first 10 lines
            print(f"  {line}")
        if len(lines) > 10:
            print("  ...")


def demo_security_headers():
    """Demo: Analyze security headers."""
    print("\n" + "="*60)
    print("SCENARIO: 'Security Header Analysis'")
    print("="*60)
    
    # Test security headers
    url = "https://httpbin.org/response-headers?X-Content-Type-Options=nosniff"
    
    print(f"\nAnalyzing headers for: {url}")
    
    result = analyze_http_headers(url, security_headers=True)
    
    print("\nSecurity Header Analysis:")
    
    if 'security_analysis' in result:
        for header, info in result['security_analysis'].items():
            status = "✓ Present" if info['present'] else "✗ Missing"
            print(f"  {header}: {status}")
            if info['present'] and 'value' in info:
                print(f"    Value: {info['value']}")
                
    if result['warnings']:
        print("\n⚠️  Security Warnings:")
        for warning in result['warnings']:
            print(f"  - {warning}")
            
    if result['recommendations']:
        print("\nSecurity Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")


def main():
    """Run all demos."""
    print("SuperSleuth Network - HTTP Diagnostics Demo")
    print("=" * 60)
    print("\nThis demo shows how Claude Code would use HTTP diagnostics")
    print("for common web/API troubleshooting scenarios.")
    
    demos = [
        ("Slow Website", demo_slow_website),
        ("API Errors", demo_api_errors),
        ("SSL Certificate Issues", demo_ssl_certificate),
        ("Web Access Problems", demo_web_access),
        ("Authentication Issues", demo_authentication),
        ("API Validation", demo_api_validation),
        ("Security Headers", demo_security_headers)
    ]
    
    for i, (name, demo_func) in enumerate(demos):
        if i > 0:
            input("\nPress Enter to continue to next demo...")
        try:
            demo_func()
        except Exception as e:
            print(f"\n❌ Demo '{name}' failed: {e}")
            
    print("\n" + "="*60)
    print("Demo completed!")
    print("\nThese functions can be called independently by Claude Code")
    print("to diagnose and troubleshoot web/HTTP issues programmatically.")


if __name__ == '__main__':
    main()