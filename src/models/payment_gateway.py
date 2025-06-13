from .base import db, BaseModel, Column, String, Boolean, DateTime, Integer, Enum as SAEnum, relationship
from enum import Enum as PyEnum
from datetime import datetime

class PaymentGatewayType(PyEnum):
    STRIPE = "stripe"
    PAYPAL = "paypal"
    NVC_GLOBAL = "nvc_global"
    CUSTOM = "custom"
    INTEROPERABLE_PAYMENT = "interoperable_payment"

class PaymentGateway(BaseModel):
    __tablename__ = 'payment_gateways'
    
    name = Column(String(128), nullable=False)
    gateway_type = Column(SAEnum(PaymentGatewayType), nullable=False)
    api_endpoint = Column(String(256))
    api_key = Column(String(256))
    webhook_secret = Column(String(256))
    ethereum_address = Column(String(64))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    transactions = relationship('Transaction', back_populates='gateway')
    
    def __repr__(self):
        return f'<PaymentGateway {self.name}>'