from . import db, BaseModel
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Numeric, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum as PyEnum
import json

class AMLStatus(PyEnum):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    FLAGGED = 'flagged'
    UNDER_REVIEW = 'under_review'

class TransactionRiskLevel(PyEnum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class TransactionPatternType(PyEnum):
    LARGE_AMOUNT = 'large_amount'
    FREQUENT_TRANSACTIONS = 'frequent_transactions'
    SUSPICIOUS_PATTERN = 'suspicious_pattern'
    UNUSUAL_ACTIVITY = 'unusual_activity'
    GEOGRAPHIC_RISK = 'geographic_risk'
    TIME_PATTERN = 'time_pattern'

class AMLTransaction(BaseModel):
    __tablename__ = 'aml_transactions'
    
    # Transaction details
    transaction_id = Column(String(36), unique=True)
    amount = Column(Numeric(20, 2))
    currency = Column(String(3))
    source_account = Column(String(50))
    destination_account = Column(String(50))
    transaction_type = Column(String(50))
    transaction_date = Column(DateTime)
    
    # Risk assessment
    risk_level = Column(SQLEnum(TransactionRiskLevel))
    risk_score = Column(Numeric(5, 2))
    risk_factors = Column(db.JSON)
    suspicious_patterns = Column(db.JSON)
    
    # AML status
    status = Column(SQLEnum(AMLStatus))
    review_date = Column(DateTime)
    reviewer_id = Column(Integer, ForeignKey('users.id'))
    review_notes = Column(Text)
    
    # Relationships
    user = relationship('User', backref='aml_transactions')
    patterns = relationship('TransactionPattern', backref='aml_transaction')
    
    def calculate_risk_score(self):
        """Calculate transaction risk score"""
        score = 0
        
        # Amount-based risk
        if self.amount > 10000:
            score += 30
        elif self.amount > 5000:
            score += 20
        elif self.amount > 1000:
            score += 10
            
        # Pattern-based risk
        if self.patterns:
            for pattern in self.patterns:
                score += pattern.risk_weight
                
        self.risk_score = score
        
        # Determine risk level
        if score >= 80:
            self.risk_level = TransactionRiskLevel.CRITICAL
        elif score >= 60:
            self.risk_level = TransactionRiskLevel.HIGH
        elif score >= 40:
            self.risk_level = TransactionRiskLevel.MEDIUM
        else:
            self.risk_level = TransactionRiskLevel.LOW
            
        return score

class TransactionPattern(BaseModel):
    __tablename__ = 'transaction_patterns'
    
    transaction_id = Column(String(36), ForeignKey('aml_transactions.transaction_id'))
    pattern_type = Column(SQLEnum(TransactionPatternType))
    pattern_data = Column(db.JSON)
    risk_weight = Column(Numeric(5, 2))
    detection_date = Column(DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.risk_weight = self._calculate_risk_weight()
        
    def _calculate_risk_weight(self):
        """Calculate risk weight based on pattern type"""
        weights = {
            TransactionPatternType.LARGE_AMOUNT: 30,
            TransactionPatternType.FREQUENT_TRANSACTIONS: 25,
            TransactionPatternType.SUSPICIOUS_PATTERN: 35,
            TransactionPatternType.UNUSUAL_ACTIVITY: 20,
            TransactionPatternType.GEOGRAPHIC_RISK: 25,
            TransactionPatternType.TIME_PATTERN: 15
        }
        return weights.get(self.pattern_type, 10)

class AMLAlert(BaseModel):
    __tablename__ = 'aml_alerts'
    
    transaction_id = Column(String(36), ForeignKey('aml_transactions.transaction_id'))
    alert_type = Column(String(50))
    severity = Column(SQLEnum(TransactionRiskLevel))
    description = Column(Text)
    status = Column(SQLEnum(AMLStatus))
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    resolved_by = Column(Integer, ForeignKey('users.id'))
    resolution_notes = Column(Text)
    
    # Relationships
    transaction = relationship('AMLTransaction', backref='alerts')
    resolver = relationship('User', backref='resolved_alerts')
    
    def mark_as_resolved(self, user_id: int, notes: str):
        """Mark alert as resolved"""
        self.status = AMLStatus.APPROVED if self.severity in [TransactionRiskLevel.LOW, TransactionRiskLevel.MEDIUM] \
                   else AMLStatus.REJECTED
        self.resolved_at = datetime.utcnow()
        self.resolved_by = user_id
        self.resolution_notes = notes
        
    def to_dict(self):
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'transaction_id': self.transaction_id,
            'alert_type': self.alert_type,
            'severity': self.severity.value,
            'description': self.description,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'resolution_notes': self.resolution_notes
        }
