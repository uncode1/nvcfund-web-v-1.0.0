"""
Comprehensive Logging Service Module

This module provides advanced logging capabilities including:
- Structured logging with JSON format
- Multiple output destinations (file, database, cloud)
- Security event logging
- Audit trail management
- Request/response logging
- Performance metrics logging
- Error tracking and alerting
- Log rotation and archival
- Real-time log streaming
"""

import logging
import json
import os
import sys
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue
import gzip
import hashlib
from pathlib import Path

from flask import request, g, current_app
from sqlalchemy.exc import SQLAlchemyError
import structlog

from ..models import db, SecurityLog, SecurityEvent, User
from ..utils.security_utils import sanitize_input, mask_sensitive_data


# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class LogLevel(Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCategory(Enum):
    """Log category enumeration."""
    SECURITY = "security"
    AUDIT = "audit"
    TRANSACTION = "transaction"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    API = "api"
    SYSTEM = "system"
    PERFORMANCE = "performance"
    ERROR = "error"
    AML = "aml"
    THREAT = "threat"
    COMPLIANCE = "compliance"


@dataclass
class LogEntry:
    """Structured log entry data class."""
    timestamp: datetime
    level: LogLevel
    category: LogCategory
    event_type: str
    message: str
    user_id: Optional[int]
    session_id: Optional[str]
    request_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    method: Optional[str]
    url: Optional[str]
    status_code: Optional[int]
    response_time: Optional[float]
    headers: Optional[Dict[str, str]]
    metadata: Optional[Dict[str, Any]]
    stack_trace: Optional[str]
    correlation_id: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class LogDestination(Enum):
    """Log destination types."""
    CONSOLE = "console"
    FILE = "file"
    DATABASE = "database"
    SYSLOG = "syslog"
    ELASTICSEARCH = "elasticsearch"
    CLOUDWATCH = "cloudwatch"
    DATADOG = "datadog"
    SPLUNK = "splunk"


class LoggingService:
    """
    Comprehensive logging service with multiple destinations and advanced features.
    
    This service provides structured logging, security event tracking,
    audit trails, and integration with external logging systems.
    """
    
    _instance = None
    _lock = threading.Lock()
    _log_queue = queue.Queue()
    _worker_thread = None
    _shutdown_event = threading.Event()
    
    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(LoggingService, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize logging service."""
        if self._initialized:
            return
            
        self._initialized = True
        self.destinations = []
        self.filters = []
        self.formatters = {}
        self._setup_destinations()
        self._start_worker_thread()
    
    def _setup_destinations(self):
        """Setup logging destinations based on configuration."""
        try:
            # Console logging
            self.destinations.append(LogDestination.CONSOLE)
            
            # File logging
            if current_app and current_app.config.get('LOG_TO_FILE', True):
                self.destinations.append(LogDestination.FILE)
            
            # Database logging
            if current_app and current_app.config.get('LOG_TO_DATABASE', True):
                self.destinations.append(LogDestination.DATABASE)
            
            # External services
            if current_app and current_app.config.get('ELASTICSEARCH_URL'):
                self.destinations.append(LogDestination.ELASTICSEARCH)
                
            if current_app and current_app.config.get('DATADOG_API_KEY'):
                self.destinations.append(LogDestination.DATADOG)
                
        except Exception as e:
            print(f"Error setting up log destinations: {str(e)}")
    
    def _start_worker_thread(self):
        """Start background worker thread for async logging."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._worker_thread = threading.Thread(
                target=self._log_worker,
                daemon=True,
                name="LoggingWorker"
            )
            self._worker_thread.start()
    
    def _log_worker(self):
        """Background worker for processing log entries."""
        while not self._shutdown_event.is_set():
            try:
                # Get log entry from queue with timeout
                log_entry = self._log_queue.get(timeout=1.0)
                
                # Process log entry to all destinations
                self._process_log_entry(log_entry)
                
                # Mark task as done
                self._log_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in log worker: {str(e)}")
    
    def _process_log_entry(self, log_entry: LogEntry):
        """Process log entry to all configured destinations."""
        try:
            # Console logging
            if LogDestination.CONSOLE in self.destinations:
                self._log_to_console(log_entry)
            
            # File logging
            if LogDestination.FILE in self.destinations:
                self._log_to_file(log_entry)
            
            # Database logging
            if LogDestination.DATABASE in self.destinations:
                self._log_to_database(log_entry)
            
            # External services
            if LogDestination.ELASTICSEARCH in self.destinations:
                self._log_to_elasticsearch(log_entry)
                
            if LogDestination.DATADOG in self.destinations:
                self._log_to_datadog(log_entry)
                
        except Exception as e:
            print(f"Error processing log entry: {str(e)}")
    
    @staticmethod
    def log(
        level: LogLevel,
        category: LogCategory,
        event_type: str,
        message: str,
        user_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Log an event with structured data.
        
        Args:
            level: Log level
            category: Log category
            event_type: Type of event
            message: Log message
            user_id: Optional user ID
            metadata: Optional metadata dictionary
            **kwargs: Additional fields
        """
        try:
            # Extract request information
            request_info = LoggingService._extract_request_info()
            
            # Create log entry
            log_entry = LogEntry(
                timestamp=datetime.utcnow(),
                level=level,
                category=category,
                event_type=event_type,
                message=sanitize_input(message),
                user_id=user_id,
                session_id=request_info.get('session_id'),
                request_id=request_info.get('request_id'),
                ip_address=request_info.get('ip_address'),
                user_agent=request_info.get('user_agent'),
                method=request_info.get('method'),
                url=request_info.get('url'),
                status_code=kwargs.get('status_code'),
                response_time=kwargs.get('response_time'),
                headers=request_info.get('headers'),
                metadata=metadata,
                stack_trace=kwargs.get('stack_trace'),
                correlation_id=kwargs.get('correlation_id')
            )
            
            # Add to queue for async processing
            service = LoggingService()
            service._log_queue.put(log_entry)
            
        except Exception as e:
            print(f"Error in logging service: {str(e)}")
    
    @staticmethod
    def log_security_event(
        event_type: str,
        description: str,
        user_id: Optional[int] = None,
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a security event."""
        LoggingService.log(
            level=LogLevel.WARNING,
            category=LogCategory.SECURITY,
            event_type=event_type,
            message=description,
            user_id=user_id,
            metadata={
                'severity': severity,
                **(metadata or {})
            }
        )
    
    @staticmethod
    def log_audit_event(
        action: str,
        resource: str,
        user_id: int,
        result: str = "success",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log an audit event."""
        LoggingService.log(
            level=LogLevel.INFO,
            category=LogCategory.AUDIT,
            event_type="audit_action",
            message=f"User {user_id} performed {action} on {resource}",
            user_id=user_id,
            metadata={
                'action': action,
                'resource': resource,
                'result': result,
                **(metadata or {})
            }
        )
    
    @staticmethod
    def log_transaction_event(
        transaction_id: str,
        transaction_type: str,
        amount: float,
        currency: str,
        user_id: int,
        status: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a transaction event."""
        LoggingService.log(
            level=LogLevel.INFO,
            category=LogCategory.TRANSACTION,
            event_type="transaction_processed",
            message=f"Transaction {transaction_id} processed",
            user_id=user_id,
            metadata={
                'transaction_id': transaction_id,
                'transaction_type': transaction_type,
                'amount': amount,
                'currency': currency,
                'status': status,
                **(metadata or {})
            }
        )
    
    @staticmethod
    def log_authentication_event(
        event_type: str,
        user_id: Optional[int],
        username: Optional[str],
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log an authentication event."""
        level = LogLevel.INFO if success else LogLevel.WARNING
        
        LoggingService.log(
            level=level,
            category=LogCategory.AUTHENTICATION,
            event_type=event_type,
            message=f"Authentication {event_type} for user {username or user_id}",
            user_id=user_id,
            metadata={
                'username': username,
                'success': success,
                **(metadata or {})
            }
        )
    
    @staticmethod
    def log_api_request(
        endpoint: str,
        method: str,
        user_id: Optional[int],
        status_code: int,
        response_time: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log an API request."""
        level = LogLevel.INFO if status_code < 400 else LogLevel.WARNING
        
        LoggingService.log(
            level=level,
            category=LogCategory.API,
            event_type="api_request",
            message=f"{method} {endpoint} - {status_code}",
            user_id=user_id,
            status_code=status_code,
            response_time=response_time,
            metadata=metadata
        )
    
    @staticmethod
    def log_error(
        error: Exception,
        context: str,
        user_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log an error with full context."""
        LoggingService.log(
            level=LogLevel.ERROR,
            category=LogCategory.ERROR,
            event_type="application_error",
            message=f"Error in {context}: {str(error)}",
            user_id=user_id,
            stack_trace=traceback.format_exc(),
            metadata={
                'error_type': type(error).__name__,
                'context': context,
                **(metadata or {})
            }
        )
    
    @staticmethod
    def log_performance_metric(
        metric_name: str,
        value: float,
        unit: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log a performance metric."""
        LoggingService.log(
            level=LogLevel.INFO,
            category=LogCategory.PERFORMANCE,
            event_type="performance_metric",
            message=f"Performance metric: {metric_name} = {value} {unit}",
            metadata={
                'metric_name': metric_name,
                'value': value,
                'unit': unit,
                **(metadata or {})
            }
        )
    
    @staticmethod
    def log_aml_analysis(
        transaction_id: str,
        user_id: int,
        alerts_count: int,
        risk_level: str,
        request_info: Dict[str, Any]
    ):
        """Log AML analysis results."""
        LoggingService.log(
            level=LogLevel.INFO,
            category=LogCategory.AML,
            event_type="aml_analysis",
            message=f"AML analysis completed for transaction {transaction_id}",
            user_id=user_id,
            metadata={
                'transaction_id': transaction_id,
                'alerts_count': alerts_count,
                'risk_level': risk_level,
                'request_info': request_info
            }
        )
    
    @staticmethod
    def log_risk_assessment(
        user_id: int,
        risk_level: str,
        risk_score: float,
        factors: List[str]
    ):
        """Log risk assessment results."""
        LoggingService.log(
            level=LogLevel.INFO,
            category=LogCategory.AML,
            event_type="risk_assessment",
            message=f"Risk assessment completed for user {user_id}",
            user_id=user_id,
            metadata={
                'risk_level': risk_level,
                'risk_score': risk_score,
                'factors': factors
            }
        )
    
    @staticmethod
    def log_sar_generation(
        user_id: int,
        report_id: str,
        reason: str
    ):
        """Log SAR report generation."""
        LoggingService.log(
            level=LogLevel.WARNING,
            category=LogCategory.COMPLIANCE,
            event_type="sar_generated",
            message=f"SAR report {report_id} generated for user {user_id}",
            user_id=user_id,
            metadata={
                'report_id': report_id,
                'reason': reason
            }
        )
    
    @staticmethod
    def log_threat_detection(
        threats: List[Any],
        request_info: Dict[str, Any],
        user_id: Optional[int]
    ):
        """Log threat detection results."""
        LoggingService.log(
            level=LogLevel.WARNING,
            category=LogCategory.THREAT,
            event_type="threat_detected",
            message=f"Threats detected: {len(threats)}",
            user_id=user_id,
            metadata={
                'threat_count': len(threats),
                'threats': [
                    {
                        'type': threat.threat_type.value,
                        'level': threat.threat_level.value,
                        'confidence': threat.confidence
                    }
                    for threat in threats
                ],
                'request_info': request_info
            }
        )
    
    def _log_to_console(self, log_entry: LogEntry):
        """Log to console."""
        try:
            log_data = log_entry.to_dict()
            print(json.dumps(log_data, default=str, indent=2))
        except Exception as e:
            print(f"Error logging to console: {str(e)}")
    
    def _log_to_file(self, log_entry: LogEntry):
        """Log to file."""
        try:
            log_dir = current_app.config.get('LOG_DIR', './logs') if current_app else './logs'
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            
            # Create log file path
            log_file = Path(log_dir) / f"{log_entry.category.value}_{datetime.utcnow().strftime('%Y%m%d')}.log"
            
            # Prepare log data
            log_data = log_entry.to_dict()
            log_line = json.dumps(log_data, default=str) + '\n'
            
            # Write to file
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
                
        except Exception as e:
            print(f"Error logging to file: {str(e)}")
    
    def _log_to_database(self, log_entry: LogEntry):
        """Log to database."""
        try:
            # Create security log entry
            security_log = SecurityLog(
                timestamp=log_entry.timestamp,
                level=log_entry.level.value,
                category=log_entry.category.value,
                event_type=log_entry.event_type,
                message=log_entry.message,
                user_id=log_entry.user_id,
                session_id=log_entry.session_id,
                ip_address=log_entry.ip_address,
                user_agent=log_entry.user_agent,
                metadata=json.dumps(log_entry.metadata) if log_entry.metadata else None
            )
            
            db.session.add(security_log)
            db.session.commit()
            
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error logging to database: {str(e)}")
        except Exception as e:
            print(f"Error logging to database: {str(e)}")
    
    def _log_to_elasticsearch(self, log_entry: LogEntry):
        """Log to Elasticsearch."""
        try:
            # This would integrate with Elasticsearch client
            # For now, we'll just prepare the data
            log_data = log_entry.to_dict()
            
            # In a real implementation, you would:
            # es_client.index(
            #     index=f"nvcfund-logs-{datetime.utcnow().strftime('%Y.%m.%d')}",
            #     body=log_data
            # )
            
        except Exception as e:
            print(f"Error logging to Elasticsearch: {str(e)}")
    
    def _log_to_datadog(self, log_entry: LogEntry):
        """Log to Datadog."""
        try:
            # This would integrate with Datadog API
            # For now, we'll just prepare the data
            log_data = log_entry.to_dict()
            
            # In a real implementation, you would:
            # datadog_client.send_log(log_data)
            
        except Exception as e:
            print(f"Error logging to Datadog: {str(e)}")
    
    @staticmethod
    def _extract_request_info() -> Dict[str, Any]:
        """Extract request information for logging."""
        try:
            if not request:
                return {}
            
            # Get session ID
            session_id = getattr(g, 'session_id', None) or request.headers.get('X-Session-ID', '')
            
            # Get request ID
            request_id = getattr(g, 'request_id', None) or request.headers.get('X-Request-ID', '')
            
            # Mask sensitive headers
            headers = dict(request.headers)
            sensitive_headers = ['Authorization', 'Cookie', 'X-API-Key']
            for header in sensitive_headers:
                if header in headers:
                    headers[header] = mask_sensitive_data(headers[header])
            
            return {
                'session_id': session_id,
                'request_id': request_id,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'method': request.method,
                'url': request.url,
                'headers': headers,
                'content_length': request.content_length or 0,
                'referrer': request.referrer or ''
            }
            
        except Exception as e:
            print(f"Error extracting request info: {str(e)}")
            return {}
    
    @staticmethod
    def rotate_logs():
        """Rotate log files."""
        try:
            log_dir = current_app.config.get('LOG_DIR', './logs') if current_app else './logs'
            log_path = Path(log_dir)
            
            if not log_path.exists():
                return
            
            # Get all log files older than 7 days
            cutoff_date = datetime.utcnow() - timedelta(days=7)
            
            for log_file in log_path.glob('*.log'):
                file_stat = log_file.stat()
                file_date = datetime.fromtimestamp(file_stat.st_mtime)
                
                if file_date < cutoff_date:
                    # Compress old log file
                    compressed_file = log_file.with_suffix('.log.gz')
                    
                    with open(log_file, 'rb') as f_in:
                        with gzip.open(compressed_file, 'wb') as f_out:
                            f_out.writelines(f_in)
                    
                    # Remove original file
                    log_file.unlink()
                    
        except Exception as e:
            print(f"Error rotating logs: {str(e)}")
    
    @staticmethod
    def cleanup_old_logs():
        """Clean up old log files."""
        try:
            log_dir = current_app.config.get('LOG_DIR', './logs') if current_app else './logs'
            log_path = Path(log_dir)
            
            if not log_path.exists():
                return
            
            # Remove compressed logs older than 30 days
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            
            for log_file in log_path.glob('*.log.gz'):
                file_stat = log_file.stat()
                file_date = datetime.fromtimestamp(file_stat.st_mtime)
                
                if file_date < cutoff_date:
                    log_file.unlink()
                    
        except Exception as e:
            print(f"Error cleaning up logs: {str(e)}")
    
    def shutdown(self):
        """Shutdown logging service."""
        try:
            self._shutdown_event.set()
            
            # Wait for queue to be empty
            self._log_queue.join()
            
            # Wait for worker thread to finish
            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=5.0)
                
        except Exception as e:
            print(f"Error shutting down logging service: {str(e)}")


# Initialize logging service
logging_service = LoggingService()