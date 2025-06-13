from .base import db, BaseModel, Column, String, Boolean, DateTime, Integer, Enum as SAEnum, relationship, Numeric, ForeignKey
from enum import Enum as PyEnum
from datetime import datetime

class AssetType(PyEnum):
    CASH = "CASH"
    TREASURY_BOND = "TREASURY_BOND"
    CORPORATE_BOND = "CORPORATE_BOND"
    SOVEREIGN_BOND = "SOVEREIGN_BOND"
    EQUITY = "EQUITY"
    REAL_ESTATE = "REAL_ESTATE"
    COMMODITY = "COMMODITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    LOAN = "LOAN"
    COLLATERALIZED_DEBT = "COLLATERALIZED_DEBT"
    OTHER = "OTHER"

class Asset(BaseModel):
    __tablename__ = 'assets'
    
    asset_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(256), nullable=False)
    description = Column(String)
    asset_type = Column(SAEnum(AssetType), nullable=False)
    value = Column(Numeric(20, 2), nullable=False)
    currency = Column(String(3), default="USD")
    location = Column(String(256))
    custodian = Column(String(256))
    managing_institution_id = Column(Integer, ForeignKey('financial_institutions.id'))
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_date = Column(DateTime)
    last_valuation_date = Column(DateTime)
    last_verified_date = Column(DateTime)
    documentation_url = Column(String(512))
    metadata_json = Column(String)
    afd1_liquidity_pool_status = Column(String(32), default="INACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    managing_institution = relationship('FinancialInstitution', back_populates='managed_assets')
    
    def __repr__(self):
        return f'<Asset {self.asset_id}: {self.name}>'