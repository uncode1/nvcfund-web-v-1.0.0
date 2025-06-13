"""
Database model for security logs.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class SecurityLog(Base):
    """Security log database model."""
    __tablename__ = 'security_logs'

    id = Column(Integer, primary_key=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    source = Column(String(100), nullable=False)
    environment = Column(String(50), nullable=False)
    details = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<SecurityLog {self.id} - {self.event_type} ({self.severity})>"

    def to_dict(self):
        """Convert log entry to dictionary."""
        return {
            'id': self.id,
            'event_type': self.event_type,
            'severity': self.severity,
            'source': self.source,
            'environment': self.environment,
            'details': json.loads(self.details),
            'timestamp': self.timestamp.isoformat()
        }
