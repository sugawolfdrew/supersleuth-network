"""
Centralized event logging system for SuperSleuth Network
Provides real-time event streaming and persistent log storage
"""

import json
import time
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
import sqlite3
from contextlib import contextmanager


class EventType(Enum):
    """Event type classification"""
    DIAGNOSTIC_START = "diagnostic.start"
    DIAGNOSTIC_COMPLETE = "diagnostic.complete"
    DIAGNOSTIC_ERROR = "diagnostic.error"
    DISCOVERY = "discovery"
    PERFORMANCE = "performance"
    SECURITY = "security"
    WIFI = "wifi"
    SYSTEM = "system"
    AUTHORIZATION = "authorization"
    ALERT = "alert"
    REMEDIATION = "remediation"
    MONITORING = "monitoring"
    USER_ACTION = "user.action"
    API_CALL = "api.call"
    

class EventSeverity(Enum):
    """Event severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Event:
    """Structured event data"""
    
    def __init__(self, event_type: EventType, severity: EventSeverity,
                 source: str, message: str, data: Optional[Dict[str, Any]] = None,
                 session_id: Optional[str] = None):
        self.id = f"{int(time.time() * 1000000)}"
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.severity = severity
        self.source = source
        self.message = message
        self.data = data or {}
        self.session_id = session_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'source': self.source,
            'message': self.message,
            'data': self.data,
            'session_id': self.session_id
        }
    
    def to_log_line(self) -> str:
        """Format event as log line"""
        return (f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] "
                f"[{self.severity.value.upper()}] [{self.source}] "
                f"{self.message}")


class EventLogger:
    """Centralized event logger with multiple output streams"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern for global logger"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize event logger"""
        if hasattr(self, '_initialized'):
            return
            
        self._initialized = True
        self.event_queue = queue.Queue()
        self.subscribers: List[Callable[[Event], None]] = []
        self.file_handlers: Dict[str, Any] = {}
        self.db_path = Path("logs/events.db")
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Configuration
        self.buffer_size = 100
        self.event_buffer: List[Event] = []
        self.running = False
        self.worker_thread = None
        
        # Initialize database
        self._init_database()
        
        # Start worker thread
        self.start()
    
    def _init_database(self):
        """Initialize SQLite database for event storage"""
        with self._get_db() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data TEXT,
                    session_id TEXT,
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Create indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_session_id ON events(session_id)')
    
    @contextmanager
    def _get_db(self):
        """Database connection context manager"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def start(self):
        """Start event processing thread"""
        if self.running:
            return
            
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_events)
        self.worker_thread.daemon = True
        self.worker_thread.start()
    
    def stop(self):
        """Stop event processing"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
    
    def log_event(self, event_type: EventType, severity: EventSeverity,
                  source: str, message: str, data: Optional[Dict[str, Any]] = None,
                  session_id: Optional[str] = None):
        """Log a new event"""
        event = Event(event_type, severity, source, message, data, session_id)
        self.event_queue.put(event)
    
    def log(self, source: str, message: str, severity: EventSeverity = EventSeverity.INFO,
            event_type: EventType = EventType.SYSTEM, **kwargs):
        """Simplified logging interface"""
        self.log_event(event_type, severity, source, message, kwargs)
    
    def debug(self, source: str, message: str, **kwargs):
        """Log debug message"""
        self.log(source, message, EventSeverity.DEBUG, **kwargs)
    
    def info(self, source: str, message: str, **kwargs):
        """Log info message"""
        self.log(source, message, EventSeverity.INFO, **kwargs)
    
    def warning(self, source: str, message: str, **kwargs):
        """Log warning message"""
        self.log(source, message, EventSeverity.WARNING, **kwargs)
    
    def error(self, source: str, message: str, **kwargs):
        """Log error message"""
        self.log(source, message, EventSeverity.ERROR, **kwargs)
    
    def critical(self, source: str, message: str, **kwargs):
        """Log critical message"""
        self.log(source, message, EventSeverity.CRITICAL, **kwargs)
    
    def subscribe(self, callback: Callable[[Event], None]):
        """Subscribe to real-time events"""
        self.subscribers.append(callback)
    
    def unsubscribe(self, callback: Callable[[Event], None]):
        """Unsubscribe from events"""
        if callback in self.subscribers:
            self.subscribers.remove(callback)
    
    def add_file_handler(self, name: str, filepath: Path, 
                        formatter: Optional[Callable[[Event], str]] = None):
        """Add file output handler"""
        self.file_handlers[name] = {
            'path': filepath,
            'formatter': formatter or (lambda e: e.to_log_line()),
            'file': None
        }
    
    def remove_file_handler(self, name: str):
        """Remove file output handler"""
        if name in self.file_handlers:
            handler = self.file_handlers[name]
            if handler['file']:
                handler['file'].close()
            del self.file_handlers[name]
    
    def _process_events(self):
        """Main event processing loop"""
        while self.running:
            try:
                # Process events with timeout
                event = self.event_queue.get(timeout=1)
                
                # Add to buffer
                self.event_buffer.append(event)
                if len(self.event_buffer) > self.buffer_size:
                    self.event_buffer.pop(0)
                
                # Store in database
                self._store_event(event)
                
                # Write to files
                self._write_to_files(event)
                
                # Notify subscribers
                self._notify_subscribers(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Event processing error: {e}")
    
    def _store_event(self, event: Event):
        """Store event in database"""
        try:
            with self._get_db() as conn:
                conn.execute('''
                    INSERT INTO events (id, timestamp, event_type, severity, 
                                      source, message, data, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.source,
                    event.message,
                    json.dumps(event.data),
                    event.session_id
                ))
        except Exception as e:
            print(f"Failed to store event: {e}")
    
    def _write_to_files(self, event: Event):
        """Write event to file handlers"""
        for name, handler in self.file_handlers.items():
            try:
                if handler['file'] is None:
                    handler['file'] = open(handler['path'], 'a')
                
                line = handler['formatter'](event)
                handler['file'].write(line + '\n')
                handler['file'].flush()
                
            except Exception as e:
                print(f"Failed to write to {name}: {e}")
    
    def _notify_subscribers(self, event: Event):
        """Notify event subscribers"""
        for subscriber in self.subscribers:
            try:
                subscriber(event)
            except Exception as e:
                print(f"Subscriber error: {e}")
    
    def get_recent_events(self, limit: int = 100, 
                         event_type: Optional[EventType] = None,
                         severity: Optional[EventSeverity] = None,
                         session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent events from buffer/database"""
        
        # First check buffer for very recent events
        filtered_events = list(self.event_buffer)
        
        # Apply filters
        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        if severity:
            filtered_events = [e for e in filtered_events if e.severity == severity]
        if session_id:
            filtered_events = [e for e in filtered_events if e.session_id == session_id]
        
        # If we need more, query database
        if len(filtered_events) < limit:
            db_events = self._query_events(
                limit - len(filtered_events),
                event_type, severity, session_id
            )
            filtered_events.extend(db_events)
        
        return [e.to_dict() if isinstance(e, Event) else e 
                for e in filtered_events[-limit:]]
    
    def _query_events(self, limit: int, event_type: Optional[EventType] = None,
                     severity: Optional[EventSeverity] = None,
                     session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query events from database"""
        
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            with self._get_db() as conn:
                cursor = conn.execute(query, params)
                events = []
                
                for row in cursor:
                    event_dict = dict(row)
                    if event_dict['data']:
                        event_dict['data'] = json.loads(event_dict['data'])
                    events.append(event_dict)
                
                return events
                
        except Exception as e:
            print(f"Failed to query events: {e}")
            return []
    
    def tail_log(self, follow: bool = True, lines: int = 10,
                 callback: Optional[Callable[[str], None]] = None):
        """Tail the event log (like tail -f)"""
        
        # Get initial lines
        recent_events = self.get_recent_events(lines)
        for event_dict in recent_events:
            line = self._format_log_line(event_dict)
            if callback:
                callback(line)
            else:
                print(line)
        
        if follow:
            # Subscribe to new events
            def print_event(event: Event):
                line = event.to_log_line()
                if callback:
                    callback(line)
                else:
                    print(line)
            
            self.subscribe(print_event)
            
            # Return unsubscribe function
            return lambda: self.unsubscribe(print_event)
    
    def _format_log_line(self, event_dict: Dict[str, Any]) -> str:
        """Format event dict as log line"""
        timestamp = event_dict['timestamp']
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        return (f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] "
                f"[{event_dict['severity'].upper()}] [{event_dict['source']}] "
                f"{event_dict['message']}")
    
    def export_session_log(self, session_id: str, filepath: Path):
        """Export all events for a session"""
        events = self._query_events(10000, session_id=session_id)
        
        with open(filepath, 'w') as f:
            for event in events:
                f.write(self._format_log_line(event) + '\n')
                if event.get('data'):
                    f.write(f"  Data: {json.dumps(event['data'], indent=2)}\n")
    
    def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get event statistics"""
        cutoff = datetime.now().timestamp() - (hours * 3600)
        
        query = '''
            SELECT 
                event_type, severity, COUNT(*) as count
            FROM events
            WHERE julianday(timestamp) > julianday('now') - ?
            GROUP BY event_type, severity
        '''
        
        stats = {
            'total_events': 0,
            'by_type': {},
            'by_severity': {},
            'error_rate': 0
        }
        
        try:
            with self._get_db() as conn:
                cursor = conn.execute(query, (hours/24,))
                
                for row in cursor:
                    event_type = row['event_type']
                    severity = row['severity']
                    count = row['count']
                    
                    stats['total_events'] += count
                    
                    if event_type not in stats['by_type']:
                        stats['by_type'][event_type] = 0
                    stats['by_type'][event_type] += count
                    
                    if severity not in stats['by_severity']:
                        stats['by_severity'][severity] = 0
                    stats['by_severity'][severity] += count
                
                # Calculate error rate
                error_count = stats['by_severity'].get('error', 0) + \
                             stats['by_severity'].get('critical', 0)
                
                if stats['total_events'] > 0:
                    stats['error_rate'] = (error_count / stats['total_events']) * 100
                
        except Exception as e:
            print(f"Failed to get statistics: {e}")
        
        return stats


# Global logger instance
event_logger = EventLogger()