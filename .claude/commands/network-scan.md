Run a network discovery scan on the specified subnet.

Usage: /network-scan [subnet]

Example: /network-scan 192.168.1.0/24

Steps:
1. Parse the subnet argument (default to 192.168.1.0/24 if not provided)
2. Create a SuperSleuth Network session with default configuration
3. Run the network discovery diagnostic
4. Display discovered devices in a formatted table
5. Log all events to the event logger
6. Show summary statistics