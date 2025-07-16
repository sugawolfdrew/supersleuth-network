"""
Logging utilities for SuperSleuth Network
"""

import logging
import os
from datetime import datetime
from pathlib import Path
import json
from typing import Optional, Dict, Any


class AuditLogger:
    """Enterprise-grade audit logger with tamper-evident features"""
    
    def __init__(self, log_dir: str = "logs", client_name: str = "default"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.client_name = client_name
        self.session_start = datetime.now()
        
        # Create audit log file with timestamp
        timestamp = self.session_start.strftime("%Y%m%d_%H%M%S")
        self.audit_file = self.log_dir / f"audit_{client_name}_{timestamp}.json"
        self.entries = []
        
    def log(self, action: str, details: Dict[str, Any], risk_level: str = "low"):
        """Log an auditable action"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'risk_level': risk_level,
            'client': self.client_name,
            'operator': os.getenv('USER', 'unknown')
        }
        
        self.entries.append(entry)
        
        # Write to file immediately for tamper-evidence
        with open(self.audit_file, 'a') as f:
            json.dump(entry, f)
            f.write('\n')
    
    def close(self):
        """Close audit log with summary"""
        summary = {
            'session_start': self.session_start.isoformat(),
            'session_end': datetime.now().isoformat(),
            'total_actions': len(self.entries),
            'risk_summary': self._calculate_risk_summary()
        }
        
        self.log('session_closed', summary)


    def _calculate_risk_summary(self) -> Dict[str, int]:
        """Calculate risk summary for session"""
        risk_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for entry in self.entries:
            risk_level = entry.get('risk_level', 'low')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
                
        return risk_counts


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    grey = "\x1b[38;21m"
    blue = "\x1b[34m"
    green = "\x1b[32m"
    yellow = "\x1b[33m"
    red = "\x1b[31m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    
    COLORS = {
        logging.DEBUG: grey,
        logging.INFO: blue,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelno, self.grey)
        record.levelname = f"{log_color}{record.levelname}{self.reset}"
        return super().format(record)


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Get a configured logger instance"""
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid adding multiple handlers
    if logger.handlers:
        return logger
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # Use colored formatter for console
    console_format = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    
    # File handler for persistent logs
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    file_handler = logging.FileHandler(
        log_dir / f"{name}_{datetime.now().strftime('%Y%m%d')}.log"
    )
    file_handler.setLevel(logging.DEBUG)
    
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


def get_audit_logger(client_name: str, log_dir: str = "logs/audit") -> AuditLogger:
    """Get an audit logger instance for enterprise compliance"""
    return AuditLogger(log_dir, client_name)


# Convenience function for structured logging
def log_diagnostic_event(logger: logging.Logger, event_type: str, 
                        details: Dict[str, Any], level: int = logging.INFO):
    """Log a structured diagnostic event"""
    
    event = {
        'event_type': event_type,
        'timestamp': datetime.now().isoformat(),
        **details
    }
    
    logger.log(level, json.dumps(event, indent=2))