"""Payroll and vendor management models."""

import json
from datetime import date, datetime
from enum import Enum as PyEnum

from .base import (
    db, BaseModel, Column, String, Boolean, DateTime, Integer, 
    Enum as SAEnum, relationship, Float, ForeignKey, Text
)


class PaymentFrequency(PyEnum):
    """Payment frequency options."""
    ONE_TIME = "one_time"
    DAILY = "daily"
    WEEKLY = "weekly"
    BI_WEEKLY = "bi-weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"
    CUSTOM = "custom"


class BillCategory(PyEnum):
    """Bill categories."""
    UTILITY = "utility"
    RENT = "rent"
    MORTGAGE = "mortgage"
    INSURANCE = "insurance"
    TAX = "tax"
    GOVERNMENT = "government"
    SUBSCRIPTION = "subscription"
    SERVICE = "service"
    OTHER = "other"


class ContractType(PyEnum):
    """Contract types."""
    FIXED_PRICE = "fixed_price"
    HOURLY = "hourly"
    RETAINER = "retainer"
    MILESTONE_BASED = "milestone_based"
    SUBSCRIPTION = "subscription"
    OTHER = "other"


class Employee(BaseModel):
    """Employee model for payroll management."""
    
    __tablename__ = 'employees'
    
    user_id = Column(Integer, ForeignKey('users.id'))
    employee_id = Column(String(64), unique=True, nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    phone = Column(String(50))
    position = Column(String(100))
    department = Column(String(100))
    hire_date = Column(DateTime, default=date.today)
    bank_account_number = Column(String(100))
    bank_routing_number = Column(String(100))
    bank_name = Column(String(150))
    payment_method = Column(String(50), default="direct_deposit")
    salary_amount = Column(Float)
    salary_frequency = Column(SAEnum(PaymentFrequency), default=PaymentFrequency.MONTHLY)
    is_active = Column(Boolean, default=True)
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship('User', backref=db.backref('employee_profile', uselist=False))
    salary_payments = relationship('SalaryPayment', back_populates='employee')

    def get_full_name(self) -> str:
        """Get employee's full name."""
        return f"{self.first_name} {self.last_name}"

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f'<Employee {self.employee_id}: {self.get_full_name()}>'


class PayrollBatch(BaseModel):
    """Payroll batch processing model."""
    
    __tablename__ = 'payroll_batches'
    
    batch_id = Column(String(64), unique=True, nullable=False)
    description = Column(String(256))
    payment_date = Column(DateTime, nullable=False)
    total_amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    status = Column(String(20), default="PENDING")  # Using TransactionStatus enum values
    processed_by = Column(Integer, ForeignKey('users.id'))
    institution_id = Column(Integer, ForeignKey('financial_institutions.id'))
    payment_method = Column(String(50), default="direct_deposit")
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    processed_by_user = relationship('User', backref=db.backref('processed_payrolls', lazy=True))
    institution = relationship('FinancialInstitution', backref=db.backref('payroll_batches', lazy=True))
    salary_payments = relationship('SalaryPayment', back_populates='payroll_batch')

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f'<PayrollBatch {self.batch_id}>'


class SalaryPayment(BaseModel):
    """Individual salary payment record."""
    
    __tablename__ = 'salary_payments'
    
    employee_id = Column(Integer, ForeignKey('employees.id'), nullable=False)
    transaction_id = Column(Integer, ForeignKey('transactions.id'))
    payroll_batch_id = Column(Integer, ForeignKey('payroll_batches.id'))
    payment_date = Column(DateTime, nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    payment_method = Column(String(50), default="direct_deposit")
    status = Column(String(20), default="PENDING")
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    description = Column(String(256))
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    employee = relationship('Employee', back_populates='salary_payments')
    transaction = relationship('Transaction', backref=db.backref('salary_payment', uselist=False))
    payroll_batch = relationship('PayrollBatch', back_populates='salary_payments')

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f'<SalaryPayment {self.employee_id} - {self.amount}>'


class Vendor(BaseModel):
    """Vendor management model."""
    
    __tablename__ = 'vendors'
    
    vendor_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(150), nullable=False)
    contact_name = Column(String(150))
    email = Column(String(120))
    phone = Column(String(50))
    address = Column(String(256))
    website = Column(String(150))
    payment_terms = Column(String(100))  # Net 30, Net 60, etc.
    bank_account_number = Column(String(100))
    bank_routing_number = Column(String(100))
    bank_name = Column(String(150))
    payment_method = Column(String(50), default="bank_transfer")
    tax_id = Column(String(50))
    is_active = Column(Boolean, default=True)
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    bills = relationship('Bill', back_populates='vendor')
    contracts = relationship('Contract', back_populates='vendor')

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f'<Vendor {self.vendor_id}: {self.name}>'


class Bill(BaseModel):
    """Bill management model."""
    
    __tablename__ = 'bills'
    
    bill_number = Column(String(64), unique=True, nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.id'), nullable=False)
    category = Column(SAEnum(BillCategory), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    issue_date = Column(DateTime, nullable=False)
    due_date = Column(DateTime, nullable=False)
    payment_date = Column(DateTime)
    status = Column(String(20), default="PENDING")
    description = Column(String(256))
    recurring = Column(Boolean, default=False)
    frequency = Column(SAEnum(PaymentFrequency), default=PaymentFrequency.ONE_TIME)
    transaction_id = Column(Integer, ForeignKey('transactions.id'))
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vendor = relationship('Vendor', back_populates='bills')
    transaction = relationship('Transaction', backref=db.backref('bill', uselist=False))

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def days_until_due(self) -> int:
        """Calculate days until due date."""
        if self.due_date:
            return (self.due_date.date() - date.today()).days
        return None

    def __repr__(self):
        return f'<Bill {self.bill_number}>'


class Contract(BaseModel):
    """Contract management model."""
    
    __tablename__ = 'contracts'
    
    contract_number = Column(String(64), unique=True, nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.id'), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    contract_type = Column(SAEnum(ContractType), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime)
    total_value = Column(Float)
    currency = Column(String(10), default="USD")
    payment_terms = Column(String(100))
    status = Column(String(50), default="active")  # active, completed, terminated
    file_path = Column(String(256))
    is_active = Column(Boolean, default=True)
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vendor = relationship('Vendor', back_populates='contracts')
    payments = relationship('ContractPayment', back_populates='contract')

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f'<Contract {self.contract_number}>'


class ContractPayment(BaseModel):
    """Contract payment tracking model."""
    
    __tablename__ = 'contract_payments'
    
    contract_id = Column(Integer, ForeignKey('contracts.id'), nullable=False)
    transaction_id = Column(Integer, ForeignKey('transactions.id'))
    payment_number = Column(String(64), unique=True, nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    payment_date = Column(DateTime)
    due_date = Column(DateTime, nullable=False)
    description = Column(String(256))
    milestone = Column(String(200))
    status = Column(String(20), default="PENDING")
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    contract = relationship('Contract', back_populates='payments')
    transaction = relationship('Transaction', backref=db.backref('contract_payment', uselist=False))

    def get_metadata(self) -> dict:
        """Get metadata as dictionary."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def __repr__(self):
        return f'<ContractPayment {self.payment_number}>'