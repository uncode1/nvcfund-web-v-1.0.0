from src.db import db, BaseModel
from .security_log import SecurityLog
from typing import Optional, Dict, Any
from sqlalchemy import Column, Enum as SQLEnum, DateTime, Integer, String, ForeignKey, Text, JSON, func
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
import json

class SecurityEventType(PyEnum):
    # Authentication Events
    LOGIN_ATTEMPT = 'login_attempt'
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILURE = 'login_failure'
    LOGOUT = 'logout'
    
    # Authorization Events
    ACCESS_GRANTED = 'access_granted'
    ACCESS_DENIED = 'access_denied'
    PERMISSION_CHANGE = 'permission_change'
    
    # Security Events
    XSS_ATTEMPT = 'xss_attempt'
    SQL_INJECTION = 'sql_injection'
    CSRF_ATTACK = 'csrf_attack'
    RCE_ATTEMPT = 'rce_attempt'
    RATE_LIMIT = 'rate_limit'
    IP_BLOCK = 'ip_block'
    FILE_UPLOAD = 'file_upload'
    
    # Audit Events
    CONFIG_CHANGE = 'config_change'
    USER_CREATE = 'user_create'
    USER_UPDATE = 'user_update'
    USER_DELETE = 'user_delete'
    
    # System Events
    STARTUP = 'startup'
    SHUTDOWN = 'shutdown'
    ERROR = 'error'
    WARNING = 'warning'

class SecurityEventSeverity(PyEnum):
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'

class SecurityEvent(BaseModel):
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True)
    event_type = Column(SQLEnum(SecurityEventType))
    severity = Column(SQLEnum(SecurityEventSeverity))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    description = Column(Text)
    event_metadata = Column(JSON)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    user = relationship('src.models.user.User', back_populates='security_events', foreign_keys='SecurityEvent.user_id', lazy='select', overlaps="security_dashboard_events")
    ip_address = Column(String(45))
    user_agent = Column(Text)
    location = Column(JSON)
    
    def __init__(self, event_type: SecurityEventType, 
                description: str,
                ip_address: str,
                user_agent: str,
                severity: SecurityEventSeverity = SecurityEventSeverity.INFO,
                metadata: Optional[Dict[str, Any]] = None,
                user_id: Optional[int] = None,
                location: Optional[Dict[str, Any]] = None):
        """Initialize a security event."""
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.event_metadata = metadata or {}
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.location = location or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'id': self.id,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
            'metadata': self.event_metadata,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'location': self.location
        }
