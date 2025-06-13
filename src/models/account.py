from .base import db, BaseModel, Column, Integer, Float, Numeric, String, Enum, ForeignKey, relationship
from decimal import Decimal
from enum import Enum as PyEnum

class AccountType(PyEnum):
    SAVINGS = 'savings'
    CHECKING = 'checking'
    FIXED_DEPOSIT = 'fixed_deposit'

class AccountStatus(PyEnum):
    ACTIVE = 'active'
    INACTIVE = 'inactive'
    BLOCKED = 'blocked'

class Account(BaseModel):
    __tablename__ = 'accounts'
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    account_number = Column(String(20), unique=True, nullable=False)
    account_type = Column(Enum(AccountType, name='accounttype'))
    status = Column(Enum(AccountStatus), default=AccountStatus.ACTIVE)
    balance = Column(db.Numeric(15, 2), default=Decimal('0.00'))
    currency = Column(String(3), default='NGN')
    interest_rate = Column(Float, default=0.0)
    
    # Relationships
    user = relationship('User', back_populates='accounts')
    transactions = relationship('Transaction', back_populates='account')
    
    def update_balance(self, amount: Decimal):
        self.balance += amount
        return self.balance
    
    def __repr__(self):
        return f'<Account {self.account_number}>'
