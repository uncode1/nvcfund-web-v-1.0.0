from .base import db, BaseModel, Column, Integer, String, Enum as SAEnum, Numeric, ForeignKey, relationship, Float, DateTime, Boolean
from decimal import Decimal
from enum import Enum as PyEnum
from datetime import datetime
import secrets

class TransactionStatus(PyEnum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REFUNDED = "REFUNDED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"
    SCHEDULED = "SCHEDULED"

class TransactionType(PyEnum):
    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"
    TRANSFER = "TRANSFER"
    PAYMENT = "PAYMENT"
    PAYOUT = "PAYOUT"
    SETTLEMENT = "SETTLEMENT"
    PAYMENT_SETTLEMENT = "PAYMENT_SETTLEMENT"
    SWIFT_LETTER_OF_CREDIT = "SWIFT_LETTER_OF_CREDIT"
    SWIFT_FUND_TRANSFER = "SWIFT_FUND_TRANSFER"
    SWIFT_INSTITUTION_TRANSFER = "SWIFT_INSTITUTION_TRANSFER"
    SWIFT_FREE_FORMAT = "SWIFT_FREE_FORMAT"
    SWIFT_TRANSFER = "SWIFT_TRANSFER"
    SWIFT_GPI_PAYMENT = "SWIFT_GPI_PAYMENT"
    SWIFT_GPI_NOTIFICATION = "SWIFT_GPI_NOTIFICATION"
    INTERNATIONAL_WIRE = "INTERNATIONAL_WIRE"
    RTGS_TRANSFER = "RTGS_TRANSFER"
    SERVER_TO_SERVER = "SERVER_TO_SERVER"
    OFF_LEDGER_TRANSFER = "OFF_LEDGER_TRANSFER"
    TOKEN_EXCHANGE = "TOKEN_EXCHANGE"
    TREASURY_FUNDING = "TREASURY_FUNDING"
    EDI_PAYMENT = "EDI_PAYMENT"
    POS_PAYMENT = "POS_PAYMENT"
    EDI_ACH_TRANSFER = "EDI_ACH_TRANSFER"
    EDI_WIRE_TRANSFER = "EDI_WIRE_TRANSFER"
    TREASURY_TRANSFER = "TREASURY_TRANSFER"
    TREASURY_INVESTMENT = "TREASURY_INVESTMENT"
    TREASURY_LOAN = "TREASURY_LOAN"
    TREASURY_DEBT_REPAYMENT = "TREASURY_DEBT_REPAYMENT"
    SALARY_PAYMENT = "SALARY_PAYMENT"
    BILL_PAYMENT = "BILL_PAYMENT"
    CONTRACT_PAYMENT = "CONTRACT_PAYMENT"
    BULK_PAYROLL = "BULK_PAYROLL"
    SWIFT_DELIVER_AGAINST_PAYMENT = "SWIFT_DELIVER_AGAINST_PAYMENT"
    STABLECOIN_TRANSFER = "STABLECOIN_TRANSFER"
    P2P_LEDGER_TRANSFER = "P2P_LEDGER_TRANSFER"
    CORRESPONDENT_SETTLEMENT = "CORRESPONDENT_SETTLEMENT"
    CRYPTO_PAYMENT = "CRYPTO_PAYMENT"
    CRYPTO_TRANSFER = "CRYPTO_TRANSFER"
    CRYPTO_EXCHANGE = "CRYPTO_EXCHANGE"
    NVCT_PAYMENT = "NVCT_PAYMENT"
    AFD1_PAYMENT = "AFD1_PAYMENT"

class PaymentMethod(PyEnum):
    CREDIT_CARD = "credit_card"
    DEBIT_CARD = "debit_card"
    BANK_TRANSFER = "bank_transfer"
    ACH = "ach"
    WIRE = "wire"
    CRYPTOCURRENCY = "cryptocurrency"
    NVCT = "nvct"
    PAYPAL = "paypal"
    SWIFT = "swift"
    RTGS = "rtgs"
    EDI = "edi"
    CASH = "cash"
    CHECK = "check"
    MONEY_ORDER = "money_order"
    STRIPE = "stripe"

class Transaction(BaseModel):
    __tablename__ = 'transactions'
    
    transaction_id = Column(String(64), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    account_id = Column(Integer, ForeignKey('accounts.id'))
    transaction_type = Column(SAEnum(TransactionType), nullable=False)
    status = Column(SAEnum(TransactionStatus), default=TransactionStatus.PENDING)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    description = Column(String(256))
    reference = Column(String(50), unique=True)
    source_account = Column(String(20))
    destination_account = Column(String(20))
    
    # Blockchain integration
    eth_transaction_hash = Column(String(128))
    
    # Institution and gateway references
    institution_id = Column(Integer, ForeignKey('financial_institutions.id'))
    gateway_id = Column(Integer, ForeignKey('payment_gateways.id'))
    
    # External system integration
    external_id = Column(String(64), index=True)
    tx_metadata_json = Column(String)
    
    # Recipient information
    recipient_name = Column(String(128))
    recipient_institution = Column(String(128))
    recipient_account = Column(String(64))
    recipient_address = Column(String(256))
    recipient_country = Column(String(64))
    recipient_bank = Column(String(128))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship('User', back_populates='transactions')
    account = relationship('Account', back_populates='transactions')
    institution = relationship('FinancialInstitution', back_populates='transactions')
    gateway = relationship('PaymentGateway', back_populates='transactions')
    
    def __init__(self, **kwargs):
        if 'transaction_id' not in kwargs:
            kwargs['transaction_id'] = secrets.token_hex(16)
        super(Transaction, self).__init__(**kwargs)
    
    def get_recipient_details(self):
        """Extract recipient details from either dedicated fields or description"""
        if self.recipient_name:
            return {
                'name': self.recipient_name,
                'institution': self.recipient_institution,
                'account': self.recipient_account,
                'address': self.recipient_address,
                'country': self.recipient_country,
                'bank': self.recipient_bank
            }

        # Legacy extraction from description
        details = {}
        if self.description:
            if ',' in self.description:
                details['name'] = self.description.split(',')[0].strip()
            else:
                details['name'] = self.description

            if 'Account:' in self.description:
                details['account'] = self.description.split('Account:')[1].strip()

        return details
    
    def __repr__(self):
        return f'<Transaction {self.transaction_id}>'
