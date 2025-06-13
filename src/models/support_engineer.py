"""
Database models for support engineer key management.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class SupportEngineerKey(Base):
    """Model for support engineer encryption keys."""
    __tablename__ = 'support_engineer_keys'

    id = Column(Integer, primary_key=True)
    engineer_id = Column(String(50), unique=True, nullable=False)
    private_key = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    permissions = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
    def __repr__(self):
        return f"<SupportEngineerKey {self.engineer_id} ({self.created_at})>"

    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'engineer_id': self.engineer_id,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat(),
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'is_active': self.is_active
        }
