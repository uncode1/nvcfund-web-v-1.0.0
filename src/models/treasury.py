from .base import db, BaseModel, Column, String, Boolean, DateTime, Integer, Enum as SAEnum, relationship, Float, ForeignKey
from enum import Enum as PyEnum
from datetime import datetime, timedelta

class TreasuryAccountType(PyEnum):
    OPERATING = "operating"
    INVESTMENT = "investment"
    RESERVE = "reserve"
    PAYROLL = "payroll"
    TAX = "tax"
    DEBT_SERVICE = "debt_service"

class TreasuryAccount(BaseModel):
    __tablename__ = 'treasury_accounts'
    
    name = Column(String(128), nullable=False)
    description = Column(String(256))
    account_type = Column(SAEnum(TreasuryAccountType), nullable=False)
    institution_id = Column(Integer, ForeignKey('financial_institutions.id'))
    account_number = Column(String(64))
    currency = Column(String(10), default="USD")
    current_balance = Column(Float, default=0.0)
    target_balance = Column(Float)
    minimum_balance = Column(Float, default=0.0)
    maximum_balance = Column(Float)
    available_balance = Column(Float, default=0.0)
    organization_id = Column(Integer)
    is_active = Column(Boolean, default=True)
    last_reconciled = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    institution = relationship('FinancialInstitution', back_populates='treasury_accounts')
    investments = relationship('TreasuryInvestment', back_populates='account')

    def update_balance(self, amount, transaction_type=None):
        """Update account balance based on transaction type"""
        from .transaction import TransactionType
        if transaction_type in [TransactionType.DEPOSIT, TransactionType.TREASURY_TRANSFER]:
            self.current_balance += amount
            self.available_balance += amount
        elif transaction_type in [TransactionType.WITHDRAWAL]:
            self.current_balance -= amount
            self.available_balance -= amount

    def is_within_limits(self):
        """Check if account balance is within defined limits"""
        if self.minimum_balance is not None and self.current_balance < self.minimum_balance:
            return False
        if self.maximum_balance is not None and self.current_balance > self.maximum_balance:
            return False
        return True

    def __repr__(self):
        return f'<TreasuryAccount {self.name}>'

class InvestmentType(PyEnum):
    CERTIFICATE_OF_DEPOSIT = "certificate_of_deposit"
    MONEY_MARKET = "money_market"
    TREASURY_BILL = "treasury_bill"
    BOND = "bond"
    COMMERCIAL_PAPER = "commercial_paper"
    OVERNIGHT_INVESTMENT = "overnight_investment"
    TIME_DEPOSIT = "time_deposit"

class InvestmentStatus(PyEnum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELED = "canceled"

class TreasuryInvestment(BaseModel):
    __tablename__ = 'treasury_investments'
    
    investment_id = Column(String(64), unique=True, nullable=False)
    account_id = Column(Integer, ForeignKey('treasury_accounts.id'))
    investment_type = Column(SAEnum(InvestmentType), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    interest_rate = Column(Float)
    start_date = Column(DateTime, nullable=False)
    maturity_date = Column(DateTime, nullable=False)
    institution_id = Column(Integer, ForeignKey('financial_institutions.id'))
    status = Column(SAEnum(InvestmentStatus), default=InvestmentStatus.PENDING)
    description = Column(String(256))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    account = relationship('TreasuryAccount', back_populates='investments')
    institution = relationship('FinancialInstitution', back_populates='investments')

    def calculate_maturity_value(self):
        """Calculate the value at maturity based on interest rate"""
        if not self.interest_rate:
            return self.amount

        days = (self.maturity_date - self.start_date).days
        annual_rate = self.interest_rate / 100

        # Simple interest calculation
        interest = self.amount * annual_rate * (days / 365)
        return self.amount + interest

    def __repr__(self):
        return f'<TreasuryInvestment {self.investment_id}>'