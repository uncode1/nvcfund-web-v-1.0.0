"""SWIFT messaging and wire transfer models."""

from .base import (
    db, BaseModel, Column, String, Boolean, DateTime, Integer, 
    Enum as SAEnum, relationship, Float, ForeignKey, Text
)
from enum import Enum as PyEnum
from datetime import datetime


class SwiftMessageStatus(PyEnum):
    """Status for SWIFT messages."""
    RECEIVED = "RECEIVED"
    PROCESSED = "PROCESSED"
    RECONCILED = "RECONCILED"
    FAILED = "FAILED"
    PENDING = "PENDING"


class SwiftMessage(BaseModel):
    """Model for storing SWIFT messages imported from various sources including GPI."""
    
    __tablename__ = 'swift_messages'
    
    message_type = Column(String(10), nullable=False)  # 103, 202, 760, etc.
    sender_bic = Column(String(15), nullable=False)
    receiver_bic = Column(String(15), nullable=False)
    reference = Column(String(35), nullable=False, index=True)
    related_reference = Column(String(35))
    amount = Column(Float)
    currency = Column(String(3))
    value_date = Column(DateTime)
    message_text = Column(Text, nullable=False)
    status = Column(String(20), default="RECEIVED", index=True)
    uploaded_by = Column(Integer, ForeignKey('users.id'))
    file_source = Column(String(255))
    source_type = Column(String(50), default="MANUAL_UPLOAD")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship('User', backref=db.backref('swift_messages', lazy=True))

    def __repr__(self):
        return f'<SwiftMessage {self.message_type} {self.reference}>'


class TelexMessageStatus(PyEnum):
    """Telex message status."""
    DRAFT = "DRAFT"
    SENT = "SENT"
    RECEIVED = "RECEIVED"
    PROCESSED = "PROCESSED"
    FAILED = "FAILED"


class TelexMessage(BaseModel):
    """Model for KTT Telex messages."""
    
    __tablename__ = 'telex_messages'
    
    message_id = Column(String(64), unique=True, nullable=False)
    sender_reference = Column(String(64), index=True)
    recipient_bic = Column(String(11), index=True)  # BIC/SWIFT code
    message_type = Column(String(10), nullable=False)  # FT, FTC, PO, etc.
    message_content = Column(Text, nullable=False)  # JSON content
    priority = Column(String(10), default="NORMAL")  # HIGH, NORMAL, LOW
    transaction_id = Column(String(64), ForeignKey('transactions.transaction_id'))
    status = Column(SAEnum(TelexMessageStatus), default=TelexMessageStatus.DRAFT)
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime)
    received_at = Column(DateTime)
    processed_at = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    transaction = relationship('Transaction', backref=db.backref('telex_messages', lazy=True))

    def __repr__(self):
        return f'<TelexMessage {self.message_id}>'


class WireTransferStatus(PyEnum):
    """Status for wire transfers."""
    PENDING = "pending"
    APPROVED = "approved"
    PROCESSING = "processing"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WireTransfer(BaseModel):
    """Model for wire transfers through correspondent banks."""
    
    __tablename__ = 'wire_transfers'
    
    reference_number = Column(String(64), unique=True, nullable=False)
    correspondent_bank_id = Column(Integer, ForeignKey('correspondent_banks.id'), nullable=False)
    transaction_id = Column(String(64), ForeignKey('transactions.transaction_id'))
    treasury_account_id = Column(Integer, ForeignKey('treasury_accounts.id'))
    transfer_id = Column(String(128))
    
    # Financial Details
    amount = Column(Float, nullable=False)
    currency = Column(String(10), nullable=False)
    purpose = Column(String(256), nullable=False)
    message_to_beneficiary = Column(Text)
    
    # Originator Information (Sender)
    originator_name = Column(String(256), nullable=False)
    originator_account = Column(String(128), nullable=False)
    originator_address = Column(Text, nullable=False)
    
    # Beneficiary Information (Recipient)
    beneficiary_name = Column(String(256), nullable=False)
    beneficiary_account = Column(String(128), nullable=False)
    beneficiary_address = Column(Text, nullable=False)
    
    # Beneficiary Bank Information
    beneficiary_bank_name = Column(String(256), nullable=False)
    beneficiary_bank_address = Column(Text, nullable=False)
    beneficiary_bank_swift = Column(String(11))
    beneficiary_bank_routing = Column(String(20))
    
    # Intermediary Bank (Optional)
    intermediary_bank_name = Column(String(256))
    intermediary_bank_swift = Column(String(11))
    
    # Status and Tracking
    status = Column(SAEnum(WireTransferStatus), default=WireTransferStatus.PENDING)
    status_description = Column(String(256))
    confirmation_receipt = Column(String(128))
    
    # Fee Information
    fee_amount = Column(Float)
    
    # Timestamps and Tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    processed_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Error information
    error_message = Column(Text)
    
    # User who created the transfer
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Relationships
    transaction = relationship(
        'Transaction', 
        foreign_keys=[transaction_id],
        backref=db.backref('wire_transfers', lazy=True)
    )
    correspondent_bank = relationship('CorrespondentBank', backref='wire_transfers')
    user = relationship('User', backref=db.backref('created_wire_transfers', lazy=True))

    def __repr__(self):
        return f'<WireTransfer {self.reference_number}>'


class WireTransferStatusHistory(BaseModel):
    """History of status changes for wire transfers."""
    
    __tablename__ = 'wire_transfer_status_history'
    
    wire_transfer_id = Column(Integer, ForeignKey('wire_transfers.id'), nullable=False)
    status = Column(SAEnum(WireTransferStatus), nullable=False)
    description = Column(String(256))
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Relationships
    wire_transfer = relationship(
        'WireTransfer', 
        backref=db.backref('status_history', lazy=True, order_by='WireTransferStatusHistory.timestamp')
    )
    user = relationship('User')
    
    def __repr__(self):
        return f"<WireTransferStatusHistory {self.status.value} at {self.timestamp}>"