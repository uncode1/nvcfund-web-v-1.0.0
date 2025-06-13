from . import db, BaseModel
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from enum import Enum as PyEnum

class MFAType(PyEnum):
    TOTP = 'totp'  # Time-based One-Time Password
    SMS = 'sms'
    EMAIL = 'email'

class MFAStatus(PyEnum):
    PENDING = 'pending'
    ACTIVE = 'active'
    INACTIVE = 'inactive'

class MFA(BaseModel):
    __tablename__ = 'mfa'
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    mfa_type = Column(SQLEnum(MFAType))
    secret_key = Column(String(255))
    status = Column(SQLEnum(MFAStatus), default=MFAStatus.PENDING)
    last_verified = Column(DateTime)
    
    user = relationship('User', backref='mfa')
    
    def generate_totp(self, current_time=None):
        """Generate a TOTP code"""
        if not current_time:
            current_time = datetime.utcnow()
        # Implementation of TOTP generation
        pass
    
    def verify_totp(self, code, current_time=None):
        """Verify a TOTP code"""
        if not current_time:
            current_time = datetime.utcnow()
        # Implementation of TOTP verification
        pass

class AuditLog(BaseModel):
    __tablename__ = 'audit_logs'
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action = Column(String(100))
    description = Column(String(500))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    success = Column(Boolean, default=True)
    
    user = relationship('User', backref='audit_logs')

class CardVault(BaseModel):
    __tablename__ = 'card_vault'
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    card_token = Column(String(100), unique=True, nullable=False)
    card_type = Column(String(20))
    last4 = Column(String(4))
    expiry_month = Column(Integer)
    expiry_year = Column(Integer)
    
    user = relationship('User', backref='card_vault')

class SensitiveData(BaseModel):
    __tablename__ = 'sensitive_data'
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    data_type = Column(String(50))  # e.g., 'card_number', 'ssn', 'passport'
    encrypted_data = Column(String(500))
    encryption_key_id = Column(String(50))
    
    user = relationship('User', backref='sensitive_data')
