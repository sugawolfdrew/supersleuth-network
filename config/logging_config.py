"""
SuperSleuth Network Logging Configuration
Sets up various log outputs and formatters
"""

from pathlib import Path
from datetime import datetime
import json

from src.core.event_logger import event_logger, Event, EventType, EventSeverity


def setup_logging():
    """
    Configure logging outputs for SuperSleuth Network
    """
    
    # Ensure log directory exists
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Main application log
    event_logger.add_file_handler(
        "main",
        log_dir / "supersleuth.log",
        formatter=lambda e: e.to_log_line()
    )
    
    # Security-specific log
    def security_formatter(event: Event) -> str:
        if event.event_type in [EventType.SECURITY, EventType.AUTHORIZATION, EventType.ALERT]:
            return f"[SECURITY] {event.to_log_line()} | Data: {json.dumps(event.data)}"
        return ""
    
    event_logger.add_file_handler(
        "security",
        log_dir / "security.log",
        formatter=security_formatter
    )
    
    # Performance metrics log (JSON format)
    def metrics_formatter(event: Event) -> str:
        if event.event_type in [EventType.PERFORMANCE, EventType.MONITORING]:
            return json.dumps({
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "message": event.message,
                "metrics": event.data
            })
        return ""
    
    event_logger.add_file_handler(
        "metrics",
        log_dir / "metrics.jsonl",
        formatter=metrics_formatter
    )
    
    # Audit log for compliance
    def audit_formatter(event: Event) -> str:
        return json.dumps({
            "event_id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "source": event.source,
            "message": event.message,
            "session_id": event.session_id,
            "data": event.data,
            "compliance_fields": {
                "user": event.data.get("user", "system"),
                "ip_address": event.data.get("ip", "unknown"),
                "action": event.data.get("action", event.message)
            }
        })
    
    event_logger.add_file_handler(
        "audit",
        log_dir / "audit.json",
        formatter=audit_formatter
    )
    
    # Daily rotating log
    daily_log = log_dir / f"supersleuth_{datetime.now().strftime('%Y%m%d')}.log"
    event_logger.add_file_handler(
        "daily",
        daily_log,
        formatter=lambda e: e.to_log_line()
    )
    
    # Error-only log
    def error_formatter(event: Event) -> str:
        if event.severity in [EventSeverity.ERROR, EventSeverity.CRITICAL]:
            return f"[{event.timestamp.isoformat()}] [{event.severity.value.upper()}] {event.source}: {event.message}\n  Details: {json.dumps(event.data, indent=2)}"
        return ""
    
    event_logger.add_file_handler(
        "errors",
        log_dir / "errors.log",
        formatter=error_formatter
    )
    
    print(f"✅ Logging configured with outputs in: {log_dir.absolute()}")
    print("   - supersleuth.log    : All events")
    print("   - security.log       : Security and authorization events")
    print("   - metrics.jsonl      : Performance metrics (JSON Lines)")
    print("   - audit.json         : Compliance audit trail")
    print("   - errors.log         : Errors and critical issues only")
    print(f"   - supersleuth_{datetime.now().strftime('%Y%m%d')}.log : Today's events")


def setup_remote_logging(endpoint: str, api_key: str = None):
    """
    Configure remote logging to external service
    """
    import requests
    
    def remote_handler(event: Event):
        """Send events to remote logging service"""
        try:
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            
            payload = {
                "service": "supersleuth_network",
                "timestamp": event.timestamp.isoformat(),
                "severity": event.severity.value,
                "event_type": event.event_type.value,
                "source": event.source,
                "message": event.message,
                "data": event.data,
                "session_id": event.session_id
            }
            
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=5
            )
            
            if not response.ok:
                print(f"Failed to send log to remote: {response.status_code}")
                
        except Exception as e:
            print(f"Remote logging error: {e}")
    
    event_logger.subscribe(remote_handler)
    print(f"✅ Remote logging configured to: {endpoint}")


def setup_syslog_output(host: str = "localhost", port: int = 514):
    """
    Configure syslog output for integration with enterprise logging
    """
    import socket
    import syslog
    
    # Map our severity to syslog priority
    severity_map = {
        EventSeverity.DEBUG: syslog.LOG_DEBUG,
        EventSeverity.INFO: syslog.LOG_INFO,
        EventSeverity.WARNING: syslog.LOG_WARNING,
        EventSeverity.ERROR: syslog.LOG_ERR,
        EventSeverity.CRITICAL: syslog.LOG_CRIT
    }
    
    def syslog_handler(event: Event):
        """Send events to syslog"""
        try:
            priority = severity_map.get(event.severity, syslog.LOG_INFO)
            message = f"SuperSleuth[{event.source}]: {event.message}"
            
            if event.data:
                message += f" | {json.dumps(event.data)}"
            
            syslog.syslog(priority, message)
            
        except Exception as e:
            print(f"Syslog error: {e}")
    
    # Open syslog connection
    syslog.openlog("SuperSleuth", syslog.LOG_PID, syslog.LOG_LOCAL0)
    event_logger.subscribe(syslog_handler)
    
    print(f"✅ Syslog output configured")


if __name__ == "__main__":
    # Example setup
    setup_logging()
    
    # Test logging
    from src.core.event_logger import event_logger, EventType, EventSeverity
    
    event_logger.log_event(
        EventType.SYSTEM,
        EventSeverity.INFO,
        "LoggingConfig",
        "Logging configuration test completed",
        {"handlers": list(event_logger.file_handlers.keys())}
    )