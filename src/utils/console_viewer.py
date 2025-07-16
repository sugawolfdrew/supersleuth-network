"""
Real-time console viewer for SuperSleuth Network events
Provides live event streaming with filtering and formatting
"""

import os
import sys
import time
import argparse
from datetime import datetime
from typing import Optional, List, Set
from pathlib import Path
import threading
import signal

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.event_logger import EventLogger, EventType, EventSeverity, Event
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
import json


class ConsoleViewer:
    """Interactive console viewer for event logs"""
    
    def __init__(self):
        self.console = Console()
        self.logger = EventLogger()
        self.running = True
        self.paused = False
        self.filters = {
            'severity': None,
            'event_type': None,
            'source': None,
            'session_id': None
        }
        self.event_buffer = []
        self.max_buffer_size = 1000
        self.display_mode = 'stream'  # 'stream', 'table', 'json'
        self.color_map = {
            EventSeverity.DEBUG: 'dim cyan',
            EventSeverity.INFO: 'green',
            EventSeverity.WARNING: 'yellow',
            EventSeverity.ERROR: 'red',
            EventSeverity.CRITICAL: 'bold red'
        }
    
    def start(self, follow: bool = True, lines: int = 20, 
              severity: Optional[str] = None,
              event_type: Optional[str] = None,
              source: Optional[str] = None,
              session_id: Optional[str] = None,
              mode: str = 'stream'):
        """Start the console viewer"""
        
        # Set filters
        if severity:
            self.filters['severity'] = EventSeverity(severity.lower())
        if event_type:
            self.filters['event_type'] = EventType(event_type)
        if source:
            self.filters['source'] = source
        if session_id:
            self.filters['session_id'] = session_id
        
        self.display_mode = mode
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_interrupt)
        
        # Get recent events
        recent_events = self.logger.get_recent_events(
            limit=lines,
            event_type=self.filters['event_type'],
            severity=self.filters['severity'],
            session_id=self.filters['session_id']
        )
        
        # Convert to Event objects
        for event_dict in recent_events:
            event = self._dict_to_event(event_dict)
            if self._should_display(event):
                self.event_buffer.append(event)
        
        if follow:
            # Subscribe to new events
            self.logger.subscribe(self._handle_new_event)
            
            # Start interactive display
            self._run_interactive()
        else:
            # Just display current events and exit
            self._display_events()
    
    def _dict_to_event(self, event_dict: dict) -> Event:
        """Convert event dictionary to Event object"""
        event = Event(
            EventType(event_dict['event_type']),
            EventSeverity(event_dict['severity']),
            event_dict['source'],
            event_dict['message'],
            event_dict.get('data', {}),
            event_dict.get('session_id')
        )
        event.id = event_dict['id']
        event.timestamp = datetime.fromisoformat(event_dict['timestamp'])
        return event
    
    def _should_display(self, event: Event) -> bool:
        """Check if event passes current filters"""
        if self.filters['severity'] and event.severity != self.filters['severity']:
            return False
        if self.filters['event_type'] and event.event_type != self.filters['event_type']:
            return False
        if self.filters['source'] and event.source != self.filters['source']:
            return False
        if self.filters['session_id'] and event.session_id != self.filters['session_id']:
            return False
        return True
    
    def _handle_new_event(self, event: Event):
        """Handle incoming event"""
        if not self.paused and self._should_display(event):
            self.event_buffer.append(event)
            if len(self.event_buffer) > self.max_buffer_size:
                self.event_buffer.pop(0)
    
    def _run_interactive(self):
        """Run interactive console with live updates"""
        
        with Live(self._create_display(), refresh_per_second=4, 
                  console=self.console) as live:
            
            # Start keyboard listener in separate thread
            keyboard_thread = threading.Thread(target=self._keyboard_listener)
            keyboard_thread.daemon = True
            keyboard_thread.start()
            
            while self.running:
                live.update(self._create_display())
                time.sleep(0.25)
    
    def _create_display(self) -> Layout:
        """Create the display layout"""
        layout = Layout()
        
        # Header
        header = self._create_header()
        
        # Main content
        if self.display_mode == 'stream':
            content = self._create_stream_view()
        elif self.display_mode == 'table':
            content = self._create_table_view()
        else:  # json
            content = self._create_json_view()
        
        # Footer with controls
        footer = self._create_footer()
        
        layout.split(
            Layout(header, size=3),
            Layout(content),
            Layout(footer, size=4)
        )
        
        return layout
    
    def _create_header(self) -> Panel:
        """Create header panel"""
        header_text = Text()
        header_text.append("🔍 SuperSleuth Network Event Viewer", style="bold blue")
        header_text.append(" | ", style="dim")
        header_text.append(f"Mode: {self.display_mode}", style="green")
        header_text.append(" | ", style="dim")
        header_text.append(f"Events: {len(self.event_buffer)}", style="cyan")
        
        if self.paused:
            header_text.append(" | ", style="dim")
            header_text.append("PAUSED", style="bold yellow blink")
        
        return Panel(header_text, style="blue")
    
    def _create_stream_view(self) -> Panel:
        """Create streaming log view"""
        lines = []
        
        for event in self.event_buffer[-30:]:  # Show last 30 events
            color = self.color_map.get(event.severity, 'white')
            
            line = Text()
            line.append(f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}] ", style="dim")
            line.append(f"[{event.severity.value.upper():8}] ", style=color)
            line.append(f"[{event.source:20}] ", style="cyan")
            line.append(event.message, style="white")
            
            if event.data:
                line.append(f" {json.dumps(event.data, separators=(',', ':'))}", style="dim")
            
            lines.append(line)
        
        content = "\n".join(str(line) for line in lines)
        return Panel(content or "No events to display", title="Event Stream")
    
    def _create_table_view(self) -> Panel:
        """Create table view of events"""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Source", style="green", width=20)
        table.add_column("Message", no_wrap=False)
        
        for event in self.event_buffer[-20:]:  # Show last 20 events
            severity_color = self.color_map.get(event.severity, 'white')
            
            table.add_row(
                event.timestamp.strftime('%H:%M:%S'),
                Text(event.severity.value, style=severity_color),
                event.event_type.value.split('.')[-1],
                event.source,
                event.message
            )
        
        return Panel(table, title="Event Table")
    
    def _create_json_view(self) -> Panel:
        """Create JSON view of recent events"""
        if not self.event_buffer:
            return Panel("No events to display", title="Event JSON")
        
        # Show last 5 events in JSON format
        events_json = []
        for event in self.event_buffer[-5:]:
            events_json.append(event.to_dict())
        
        json_str = json.dumps(events_json, indent=2, default=str)
        syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
        
        return Panel(syntax, title="Event JSON")
    
    def _create_footer(self) -> Panel:
        """Create footer with controls"""
        footer_text = Text()
        footer_text.append("Controls: ", style="bold")
        footer_text.append("[q]uit | [p]ause | [c]lear | [s]tream | [t]able | [j]son | [f]ilter", 
                          style="cyan")
        
        if any(self.filters.values()):
            footer_text.append("\nFilters: ", style="bold yellow")
            active_filters = []
            for key, value in self.filters.items():
                if value:
                    active_filters.append(f"{key}={value}")
            footer_text.append(" | ".join(active_filters), style="yellow")
        
        return Panel(footer_text, style="dim")
    
    def _keyboard_listener(self):
        """Listen for keyboard input"""
        try:
            import termios
            import tty
            
            # Save terminal settings
            old_settings = termios.tcgetattr(sys.stdin)
            
            try:
                # Set terminal to raw mode
                tty.setraw(sys.stdin.fileno())
                
                while self.running:
                    char = sys.stdin.read(1)
                    
                    if char == 'q':
                        self.running = False
                    elif char == 'p':
                        self.paused = not self.paused
                    elif char == 'c':
                        self.event_buffer.clear()
                    elif char == 's':
                        self.display_mode = 'stream'
                    elif char == 't':
                        self.display_mode = 'table'
                    elif char == 'j':
                        self.display_mode = 'json'
                    elif char == 'f':
                        # Would implement filter dialog here
                        pass
            
            finally:
                # Restore terminal settings
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                
        except ImportError:
            # termios not available (Windows)
            while self.running:
                time.sleep(1)
    
    def _handle_interrupt(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        self.running = False
        self.console.print("\n[yellow]Shutting down...[/yellow]")
        sys.exit(0)
    
    def _display_events(self):
        """Display events once and exit"""
        if self.display_mode == 'stream':
            for event in self.event_buffer:
                self.console.print(event.to_log_line())
        elif self.display_mode == 'table':
            self.console.print(self._create_table_view())
        else:
            self.console.print(self._create_json_view())


def main():
    """Main entry point for console viewer"""
    parser = argparse.ArgumentParser(
        description='SuperSleuth Network Event Console Viewer'
    )
    
    parser.add_argument('-f', '--follow', action='store_true',
                       help='Follow new events (like tail -f)')
    parser.add_argument('-n', '--lines', type=int, default=20,
                       help='Number of recent events to show')
    parser.add_argument('-s', '--severity', choices=['debug', 'info', 'warning', 'error', 'critical'],
                       help='Filter by severity level')
    parser.add_argument('-t', '--type', dest='event_type',
                       help='Filter by event type')
    parser.add_argument('--source', help='Filter by source')
    parser.add_argument('--session', dest='session_id',
                       help='Filter by session ID')
    parser.add_argument('-m', '--mode', choices=['stream', 'table', 'json'],
                       default='stream', help='Display mode')
    
    args = parser.parse_args()
    
    viewer = ConsoleViewer()
    viewer.start(
        follow=args.follow,
        lines=args.lines,
        severity=args.severity,
        event_type=args.event_type,
        source=args.source,
        session_id=args.session_id,
        mode=args.mode
    )


if __name__ == '__main__':
    main()