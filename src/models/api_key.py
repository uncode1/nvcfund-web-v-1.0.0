from datetime import datetime, timedelta
from secrets import token_urlsafe
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey
from src.db import BaseModel
from src.models.user import User

class APIKey(BaseModel):
    """Model for API keys."""
    __tablename__ = 'api_keys'

    key = Column(String(64), unique=True, nullable=False)
    description = Column(String(255))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)

    def __init__(self, user_id, description=None, expires_in_days=None):
        self.user_id = user_id
        self.description = description
        self.key = self.generate_key()
        if expires_in_days:
            self.expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    @staticmethod
    def generate_key(length=64):
        """Generate a secure API key."""
        return token_urlsafe(length)

    def is_expired(self):
        """Check if the API key has expired."""
        return self.expires_at and datetime.utcnow() > self.expires_at

    def to_dict(self):
        """Convert API key to dictionary."""
        return {
            'id': self.id,
            'key': self.key,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }
