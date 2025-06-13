"""Stablecoin and closed-loop system models."""

from .base import (
    db, BaseModel, Column, String, Boolean, DateTime, Integer, 
    Enum as SAEnum, relationship, Float, ForeignKey
)
from enum import Enum as PyEnum
from datetime import datetime
import secrets


class StablecoinAccount(BaseModel):
    """Account for NVC Token Stablecoin within the closed-loop system."""
    
    __tablename__ = 'stablecoin_accounts'
    
    account_number = Column(String(64), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    balance = Column(Float, default=0.0)
    currency = Column(String(10), default="NVCT")
    is_active = Column(Boolean, default=True)
    account_type = Column(String(20), default="INDIVIDUAL")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship('User', back_populates='stablecoin_accounts')
    ledger_entries = relationship('LedgerEntry', back_populates='account')
    
    def deposit(self, amount: float) -> None:
        """Deposit funds to the account."""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")
        self.balance += amount
        self.updated_at = datetime.utcnow()
        
    def withdraw(self, amount: float) -> None:
        """Withdraw funds from the account."""
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive")
        if amount > self.balance:
            raise ValueError("Insufficient funds")
        self.balance -= amount
        self.updated_at = datetime.utcnow()
        
    def transfer(self, destination_account, amount: float, description: str = None):
        """Transfer stablecoins to another account."""
        if amount <= 0:
            raise ValueError("Transfer amount must be positive")
        if amount > self.balance:
            raise ValueError("Insufficient funds")
            
        self.withdraw(amount)
        destination_account.deposit(amount)
        
        # Create transfer transaction record
        from .transaction import Transaction, TransactionType, TransactionStatus
        
        transaction_id = secrets.token_hex(16)
        transaction = Transaction(
            transaction_id=transaction_id,
            user_id=self.user_id,
            amount=amount,
            currency=self.currency,
            transaction_type=TransactionType.STABLECOIN_TRANSFER,
            status=TransactionStatus.COMPLETED,
            description=description or f"Transfer to {destination_account.account_number}",
            recipient_name=f"Account: {destination_account.account_number}",
            recipient_account=destination_account.account_number
        )
        db.session.add(transaction)
        
        # Create ledger entries
        debit_entry = LedgerEntry(
            transaction_id=transaction_id,
            account_id=self.id,
            entry_type='DEBIT',
            amount=amount,
            description=f"Transfer to {destination_account.account_number}"
        )
        db.session.add(debit_entry)
        
        credit_entry = LedgerEntry(
            transaction_id=transaction_id,
            account_id=destination_account.id,
            entry_type='CREDIT',
            amount=amount,
            description=f"Transfer from {self.account_number}"
        )
        db.session.add(credit_entry)
        
        return transaction
    
    def __repr__(self):
        return f'<StablecoinAccount {self.account_number}>'


class LedgerEntry(BaseModel):
    """Double-entry accounting ledger for the closed-loop system."""
    
    __tablename__ = 'ledger_entries'
    
    transaction_id = Column(String(64), nullable=False, index=True)
    account_id = Column(Integer, ForeignKey('stablecoin_accounts.id'), nullable=False)
    entry_type = Column(String(10), nullable=False)  # DEBIT or CREDIT
    amount = Column(Float, nullable=False)
    balance_after = Column(Float)  # Running balance after this entry
    description = Column(String(256))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    account = relationship('StablecoinAccount', back_populates='ledger_entries')
    
    def __repr__(self):
        return f'<LedgerEntry {self.entry_type} {self.amount}>'


class CorrespondentBank(BaseModel):
    """Model for correspondent banks providing global banking integration."""
    
    __tablename__ = 'correspondent_banks'
    
    name = Column(String(128), nullable=False)
    bank_code = Column(String(20), unique=True, nullable=False)
    swift_code = Column(String(11))
    ach_routing_number = Column(String(9))
    clearing_account_number = Column(String(64))
    stablecoin_account_id = Column(Integer, ForeignKey('stablecoin_accounts.id'))
    settlement_threshold = Column(Float, default=10000.0)
    settlement_fee_percentage = Column(Float, default=0.5)
    is_active = Column(Boolean, default=True)
    supports_ach = Column(Boolean, default=False)
    supports_swift = Column(Boolean, default=False)
    supports_wire = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    stablecoin_account = relationship(
        'StablecoinAccount', 
        backref=db.backref('correspondent_bank', uselist=False)
    )
    
    def __repr__(self):
        return f'<CorrespondentBank {self.name}>'


class SettlementBatchStatus(PyEnum):
    """Status for settlement batches."""
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SettlementBatch(BaseModel):
    """Model for batched settlements with correspondent banks."""
    
    __tablename__ = 'settlement_batches'
    
    batch_id = Column(String(64), unique=True, nullable=False)
    correspondent_bank_id = Column(Integer, ForeignKey('correspondent_banks.id'), nullable=False)
    total_amount = Column(Float, nullable=False)
    fee_amount = Column(Float, nullable=False)
    net_amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    status = Column(SAEnum(SettlementBatchStatus), default=SettlementBatchStatus.PENDING)
    settlement_method = Column(String(20))  # ACH, SWIFT, WIRE
    external_reference = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Relationships
    correspondent_bank = relationship(
        'CorrespondentBank', 
        backref=db.backref('settlement_batches', lazy=True)
    )
    
    def __repr__(self):
        return f'<SettlementBatch {self.batch_id}>'