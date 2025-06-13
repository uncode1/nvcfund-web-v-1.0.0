from .base import db, BaseModel, Column, String, Boolean, DateTime, Integer, Enum as SAEnum, relationship, Float
from enum import Enum as PyEnum
from datetime import datetime

class FinancialInstitutionType(PyEnum):
    BANK = "bank"
    CREDIT_UNION = "credit_union"
    INVESTMENT_FIRM = "investment_firm"
    CENTRAL_BANK = "central_bank"
    GOVERNMENT = "government"
    OTHER = "other"

class FinancialInstitution(BaseModel):
    __tablename__ = 'financial_institutions'
    
    name = Column(String(128), nullable=False)
    institution_type = Column(SAEnum(FinancialInstitutionType), nullable=False)
    api_endpoint = Column(String(256))
    api_key = Column(String(256))
    ethereum_address = Column(String(64))
    swift_code = Column(String(11))
    ach_routing_number = Column(String(9))
    account_number = Column(String(64))
    metadata_json = Column(String)
    is_active = Column(Boolean, default=True)
    rtgs_enabled = Column(Boolean, default=False)
    s2s_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    transactions = relationship('Transaction', back_populates='institution')
    managed_assets = relationship('Asset', back_populates='managing_institution')
    treasury_accounts = relationship('TreasuryAccount', back_populates='institution')
    investments = relationship('TreasuryInvestment', back_populates='institution')
    
    def __repr__(self):
        return f'<FinancialInstitution {self.name}>'