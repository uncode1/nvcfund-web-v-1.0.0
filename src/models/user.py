from .base import db, BaseModel, Column, String, Boolean, DateTime, Integer, Enum as SAEnum, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import enum
from datetime import datetime

class UserRole(enum.Enum):
    ADMIN = "admin"
    USER = "user"
    API = "api"
    DEVELOPER = "developer"

class User(BaseModel, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    username = Column(String(64), unique=True)
    password_hash = Column(String(256))
    first_name = Column(String(100))
    last_name = Column(String(100))
    phone_number = Column(String(50))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(SAEnum(UserRole), default=UserRole.USER)
    api_key = Column(String(64), unique=True)
    ethereum_address = Column(String(64))
    ethereum_private_key = Column(String(256))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    organization = Column(String(150))
    country = Column(String(100))
    newsletter = Column(Boolean, default=False)
    email_verified = Column(Boolean, default=False)
    external_customer_id = Column(String(64), index=True)
    external_account_id = Column(String(64), index=True)
    external_account_type = Column(String(32))
    external_account_currency = Column(String(3))
    external_account_status = Column(String(16))
    last_sync = Column(DateTime)

    # Relationships
    accounts = relationship('Account', back_populates='user')
    transactions = relationship('Transaction', back_populates='user')
    blockchain_accounts = relationship('BlockchainAccount', back_populates='user')
    stablecoin_accounts = relationship('StablecoinAccount', back_populates='user')
    security_events = relationship('src.models.security_event.SecurityEvent', back_populates='user', foreign_keys='src.models.security_event.SecurityEvent.user_id', lazy='select', cascade='all, delete-orphan')
    security_dashboard_events = relationship('src.models.security_dashboard.SecurityDashboardEvent', back_populates='user', foreign_keys='SecurityDashboardEvent.user_id', lazy='select', overlaps="security_events")
    alert_preferences = relationship('src.models.security_dashboard.AlertPreference', back_populates='user', foreign_keys='AlertPreference.user_id', lazy='select')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username or self.email

    def __repr__(self):
        return f'<User {self.email}>'
