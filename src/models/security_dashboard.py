from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Enum as SAEnum
from sqlalchemy.orm import relationship
from enum import Enum
from src.db import BaseModel
from .security_event import SecurityEvent as BaseSecurityEvent

# Enum definitions

# Enum definitions
class ThreatLevel(str, Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class ThreatType(str, Enum):
    WEB = 'web'
    NETWORK = 'network'
    APPLICATION = 'application'
    AUTHENTICATION = 'authentication'
    FRAUD = 'fraud'
    AML = 'aml'
    SYSTEM = 'system'
    LOGIN_ATTEMPT = 'login_attempt'
    SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    SECURITY_VIOLATION = 'security_violation'
    SYSTEM_ALERT = 'system_alert'
    AUTHENTICATION_FAILURE = 'authentication_failure'

# Create SQLAlchemy Enum types
ThreatLevelEnum = SAEnum(ThreatLevel)
ThreatTypeEnum = SAEnum(ThreatType)

class SecurityDashboardEvent(BaseSecurityEvent):
    __tablename__ = 'security_dashboard_events'
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, ForeignKey('security_events.id'), primary_key=True)
    threat_type = Column(ThreatTypeEnum, nullable=False)
    threat_description = Column(String(500), nullable=False)
    details = Column(String(1000))
    module = Column(String(50))  # Module name
    function = Column(String(50))  # Function name
    status = Column(String(20), default='active')  # active, resolved, ignored
    resolved_at = Column(DateTime)
    resolution_notes = Column(String(500))
    
    user = relationship('src.models.user.User', back_populates='security_dashboard_events', foreign_keys='SecurityEvent.user_id', lazy='select', overlaps="security_events")

class NetworkThreat(BaseModel):
    __tablename__ = 'network_threats'
    
    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey('security_events.id'))
    protocol_stack = Column(String(200))  # OSI/TCP-IP layers involved
    packet_size = Column(Integer)
    packet_count = Column(Integer)
    flags = Column(String(50))  # TCP flags
    ttl = Column(Integer)
    checksum = Column(String(50))
    sequence_number = Column(Integer)
    
    event = relationship('SecurityEvent', backref='network_threat')

class AlertPreference(BaseModel):
    __tablename__ = 'alert_preferences'
    
    id = Column(Integer, primary_key=True)
    alert_type = Column(ThreatLevelEnum, nullable=False)
    alert_level = Column(ThreatLevelEnum, nullable=False)
    enabled = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('src.models.user.User', back_populates='alert_preferences', foreign_keys='AlertPreference.user_id', lazy='select')
    email_enabled = Column(Boolean, default=True)
    slack_enabled = Column(Boolean, default=False)
    telegram_enabled = Column(Boolean, default=False)
    whatsapp_enabled = Column(Boolean, default=False)
    sms_enabled = Column(Boolean, default=True)
    custom_webhook = Column(String(200))  # For custom integrations


