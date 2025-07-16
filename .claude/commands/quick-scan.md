Run a quick diagnostic scan with essential checks.

Usage: /quick-scan [target]

Example: /quick-scan 192.168.1.1

Steps:
1. Parse target (IP, hostname, or 'local' for full network)
2. Initialize SuperSleuth with minimal configuration
3. Run these diagnostics in sequence:
   - Network discovery (if local network)
   - Basic connectivity test
   - Performance quick test (bandwidth, latency)
   - Security port scan
4. Generate a concise summary report
5. Highlight any critical issues found
6. Suggest next steps if problems detected