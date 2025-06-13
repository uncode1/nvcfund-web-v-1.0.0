import logging
from datetime import datetime
from typing import Dict, Any, Optional
from src.models.security_event import SecurityEvent, SecurityEventType, SecurityEventSeverity
import json
from src.security.config import SecurityConfig

logger = logging.getLogger(__name__)

class SecurityLogger:
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup security logging configuration"""
        # Create security log handler
        security_handler = logging.FileHandler(self.config.SECURITY_LOG_FILE)
        security_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(security_handler)
        
    def log_event(self, event_type: SecurityEventType, 
                 severity: SecurityEventSeverity = SecurityEventSeverity.INFO,
                 **kwargs) -> SecurityEvent:
        """Log a security event with detailed information"""
        # Create database event
        event = SecurityEvent().log_event(event_type, severity, **kwargs)
        
        # Create log message
        log_message = self._format_log_message(event_type, severity, **kwargs)
        
        # Log to different levels based on severity
        if severity == SecurityEventSeverity.INFO:
            logger.info(log_message)
        elif severity == SecurityEventSeverity.WARNING:
            logger.warning(log_message)
        elif severity == SecurityEventSeverity.ERROR:
            logger.error(log_message)
        else:  # CRITICAL
            logger.critical(log_message)
            
        return event
    
    def _format_log_message(self, event_type: SecurityEventType, 
                          severity: SecurityEventSeverity,
                          **kwargs) -> str:
        """Format log message with all relevant details"""
        message = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type.value,
            'severity': severity.value,
            'source': {
                'ip': kwargs.get('source_ip', request.remote_addr),
                'port': kwargs.get('source_port', request.environ.get('REMOTE_PORT')),
                'user_agent': kwargs.get('source_user_agent', request.headers.get('User-Agent')),
                'country': kwargs.get('source_country', 'Unknown')
            },
            'target': {
                'user_id': kwargs.get('target_user_id'),
                'endpoint': kwargs.get('target_endpoint', request.path),
                'resource': kwargs.get('target_resource')
            },
            'request': {
                'method': kwargs.get('request_method', request.method),
                'path': kwargs.get('request_path', request.path),
                'headers': dict(request.headers),
                'body': kwargs.get('request_body', request.get_data(as_text=True))
            },
            'response': {
                'status': kwargs.get('response_status'),
                'headers': kwargs.get('response_headers', {}),
                'body': kwargs.get('response_body', '')
            },
            'metadata': kwargs.get('metadata', {})
        }
        
        return json.dumps(message)
    
    def log_authentication(self, user_id: int, success: bool, **kwargs):
        """Log authentication events"""
        event_type = SecurityEventType.LOGIN_SUCCESS if success else SecurityEventType.LOGIN_FAILURE
        severity = SecurityEventSeverity.INFO if success else SecurityEventSeverity.WARNING
        
        return self.log_event(
            event_type=event_type,
            severity=severity,
            target_user_id=user_id,
            **kwargs
        )
    
    def log_authorization(self, user_id: int, success: bool, resource: str, **kwargs):
        """Log authorization events"""
        event_type = SecurityEventType.ACCESS_GRANTED if success else SecurityEventType.ACCESS_DENIED
        severity = SecurityEventSeverity.INFO if success else SecurityEventSeverity.WARNING
        
        return self.log_event(
            event_type=event_type,
            severity=severity,
            target_user_id=user_id,
            target_resource=resource,
            **kwargs
        )
    
    def log_security_event(self, event_type: SecurityEventType, **kwargs):
        """Log security events"""
        severity = SecurityEventSeverity.WARNING
        
        if event_type in [SecurityEventType.XSS_ATTEMPT, 
                         SecurityEventType.SQL_INJECTION,
                         SecurityEventType.CSRF_ATTACK,
                         SecurityEventType.RCE_ATTEMPT]:
            severity = SecurityEventSeverity.CRITICAL
        
        return self.log_event(
            event_type=event_type,
            severity=severity,
            **kwargs
        )
    
    def log_audit_event(self, user_id: int, event_type: SecurityEventType, **kwargs):
        """Log audit events"""
        return self.log_event(
            event_type=event_type,
            severity=SecurityEventSeverity.INFO,
            target_user_id=user_id,
            **kwargs
        )
    
    def log_system_event(self, event_type: SecurityEventType, **kwargs):
        """Log system events"""
        severity = SecurityEventSeverity.INFO
        
        if event_type in [SecurityEventType.ERROR, SecurityEventType.WARNING]:
            severity = SecurityEventSeverity.CRITICAL if event_type == SecurityEventType.ERROR else SecurityEventSeverity.WARNING
        
        return self.log_event(
            event_type=event_type,
            severity=severity,
            **kwargs
        )
    
    def get_security_events(self, 
                          event_type: Optional[SecurityEventType] = None,
                          severity: Optional[SecurityEventSeverity] = None,
                          start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None,
                          limit: int = 100) -> list:
        """Get security events with filtering"""
        query = SecurityEvent.query
        
        if event_type:
            query = query.filter_by(event_type=event_type)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if start_date:
            query = query.filter(SecurityEvent.timestamp >= start_date)
        
        if end_date:
            query = query.filter(SecurityEvent.timestamp <= end_date)
        
        return query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
