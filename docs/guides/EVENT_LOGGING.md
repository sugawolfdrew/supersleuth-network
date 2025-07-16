# SuperSleuth Network Event Logging System

## Overview

SuperSleuth Network includes a comprehensive event logging system that captures all system activities, diagnostics, security events, and performance metrics. This provides complete visibility into network operations and enables real-time monitoring, debugging, and compliance auditing.

## Quick Start

### View Real-Time Events

```bash
# Follow all events in real-time (like tail -f)
python3 event_viewer.py -f

# View events in table format
python3 event_viewer.py -f -m table

# Filter by severity
python3 event_viewer.py -f -s error     # Errors only
python3 event_viewer.py -f -s warning   # Warnings and above

# Filter by event type
python3 event_viewer.py -f -t security  # Security events
python3 event_viewer.py -f -t performance  # Performance metrics
```

### Run the Demo

```bash
# See various event types in action
python3 examples/event_logging_demo.py
```

## Event Types

### Diagnostic Events
- `diagnostic.start` - Diagnostic test initiated
- `diagnostic.complete` - Test completed successfully
- `diagnostic.error` - Test encountered an error

### Discovery Events
- `discovery` - Network device or service discovered

### Performance Events
- `performance` - Performance metrics and measurements

### Security Events
- `security` - Security findings and vulnerabilities
- `authorization` - Authorization requests and decisions
- `alert` - Security alerts and warnings

### System Events
- `system` - System status and configuration changes
- `monitoring` - Continuous monitoring status
- `api.call` - API requests and responses
- `user.action` - User-initiated actions
- `remediation` - Remediation actions taken

## Event Severity Levels

- `DEBUG` - Detailed diagnostic information
- `INFO` - Normal operational messages
- `WARNING` - Warning conditions that may need attention
- `ERROR` - Error conditions that need investigation
- `CRITICAL` - Critical issues requiring immediate action

## Log File Locations

All logs are stored in the `logs/` directory:

- `supersleuth.log` - Main application log with all events
- `security.log` - Security-specific events and alerts
- `metrics.jsonl` - Performance metrics in JSON Lines format
- `audit.json` - Complete audit trail for compliance
- `errors.log` - Errors and critical issues only
- `supersleuth_YYYYMMDD.log` - Daily rotating logs
- `events.db` - SQLite database with all events

## Console Viewer Controls

When running the interactive console viewer:

- `q` - Quit the viewer
- `p` - Pause/unpause event stream
- `c` - Clear the current display
- `s` - Switch to stream view
- `t` - Switch to table view
- `j` - Switch to JSON view
- `f` - Open filter dialog (if implemented)

## Web Dashboard Integration

The web dashboard automatically displays events:

1. Start the dashboard:
   ```bash
   python3 dashboard_launcher.py
   ```

2. Events appear in real-time in the dashboard

3. Access event APIs:
   - `GET /api/events/recent?limit=50` - Get recent events
   - `GET /api/events/stream` - Server-sent event stream

## Programmatic Access

### Logging Events

```python
from src.core.event_logger import event_logger, EventType, EventSeverity

# Log a simple event
event_logger.log(
    "MyModule",
    "Operation completed successfully"
)

# Log with specific type and severity
event_logger.log_event(
    EventType.SECURITY,
    EventSeverity.WARNING,
    "SecurityScanner",
    "Weak encryption detected",
    {
        "protocol": "WPA",
        "recommendation": "Upgrade to WPA3"
    }
)

# Convenience methods
event_logger.error("MyModule", "Connection failed", error="Timeout")
event_logger.warning("MyModule", "High latency detected", latency=250)
```

### Subscribing to Events

```python
# Define callback
def handle_security_events(event):
    if event.event_type == EventType.SECURITY:
        print(f"Security event: {event.message}")

# Subscribe
event_logger.subscribe(handle_security_events)

# Unsubscribe when done
event_logger.unsubscribe(handle_security_events)
```

### Querying Events

```python
# Get recent events
events = event_logger.get_recent_events(
    limit=100,
    event_type=EventType.PERFORMANCE,
    severity=EventSeverity.WARNING
)

# Get event statistics
stats = event_logger.get_statistics(hours=24)
print(f"Total events: {stats['total_events']}")
print(f"Error rate: {stats['error_rate']}%")
```

## Configuration

### Basic Setup

```python
from config.logging_config import setup_logging

# Configure all log outputs
setup_logging()
```

### Remote Logging

```python
from config.logging_config import setup_remote_logging

# Send events to remote service
setup_remote_logging(
    endpoint="https://logs.example.com/api/events",
    api_key="your-api-key"
)
```

### Syslog Integration

```python
from config.logging_config import setup_syslog_output

# Send to local syslog
setup_syslog_output()

# Or to remote syslog server
setup_syslog_output(host="syslog.company.com", port=514)
```

## Custom Log Handlers

```python
# Add custom file handler
event_logger.add_file_handler(
    "custom",
    Path("logs/custom.log"),
    formatter=lambda e: f"{e.timestamp} | {e.message}"
)

# Add custom subscriber for alerts
def alert_handler(event):
    if event.severity == EventSeverity.CRITICAL:
        send_email_alert(event.message)
        
event_logger.subscribe(alert_handler)
```

## Integration Examples

### Splunk Integration

```python
# Configure JSON output for Splunk
event_logger.add_file_handler(
    "splunk",
    Path("/var/log/supersleuth/splunk.json"),
    formatter=lambda e: json.dumps({
        "time": e.timestamp.timestamp(),
        "source": "supersleuth",
        "sourcetype": "_json",
        "event": e.to_dict()
    })
)
```

### ELK Stack Integration

```python
# Send to Elasticsearch via Logstash
def logstash_formatter(event):
    return json.dumps({
        "@timestamp": event.timestamp.isoformat(),
        "@version": "1",
        "host": socket.gethostname(),
        "service": "supersleuth",
        "level": event.severity.value,
        "logger": event.source,
        "message": event.message,
        "event_type": event.event_type.value,
        "data": event.data
    })
```

## Best Practices

1. **Use Appropriate Severity Levels**
   - DEBUG for detailed diagnostic info
   - INFO for normal operations
   - WARNING for potential issues
   - ERROR for failures
   - CRITICAL for urgent issues

2. **Include Structured Data**
   ```python
   # Good - includes context
   event_logger.log("Scanner", "Port scan complete", 
                   ports_scanned=65535, open_ports=5, duration=45.2)
   
   # Less useful
   event_logger.log("Scanner", "Port scan complete")
   ```

3. **Use Consistent Event Types**
   - Group related events under the same type
   - Makes filtering and analysis easier

4. **Include Session IDs**
   - Helps correlate events across a diagnostic session
   - Essential for troubleshooting

5. **Monitor Error Rates**
   - Set up alerts for high error rates
   - Review error logs regularly

## Troubleshooting

### Events Not Appearing

1. Check if event logger is running:
   ```python
   print(event_logger.running)  # Should be True
   ```

2. Verify log directory exists:
   ```bash
   ls -la logs/
   ```

3. Check for errors in console:
   ```bash
   python3 event_viewer.py -f -s error
   ```

### High Memory Usage

- Reduce event buffer size:
  ```python
  event_logger.buffer_size = 50  # Default is 100
  ```

- Clear old events from database:
  ```sql
  DELETE FROM events WHERE julianday('now') - julianday(timestamp) > 30;
  ```

### Performance Impact

- Use DEBUG level sparingly in production
- Consider filtering events before logging
- Use batch operations when possible

## Security Considerations

1. **Sensitive Data**
   - Never log passwords or API keys
   - Sanitize user input before logging
   - Use data classification in events

2. **Access Control**
   - Restrict log file permissions
   - Use encryption for remote logging
   - Implement log rotation and retention policies

3. **Compliance**
   - Ensure logs meet regulatory requirements
   - Implement tamper-proof audit trails
   - Regular log reviews and monitoring