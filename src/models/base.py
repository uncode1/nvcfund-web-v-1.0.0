from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Numeric, Enum, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship

from . import db

class BaseModel(db.Model):
    """Base model class with common fields and methods."""
    __abstract__ = True
    
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def save(self):
        """Save the model instance to the database."""
        db.session.add(self)
        db.session.commit()
        return self
    
    def delete(self):
        """Delete the model instance from the database."""
        db.session.delete(self)
        db.session.commit()
        return self
    
    def to_dict(self):
        """Convert model instance to dictionary."""
        data = {
            'id': self.id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        # Add model-specific fields if they exist
        if hasattr(self, 'user_id'):
            data['user_id'] = self.user_id
        if hasattr(self, 'account_number'):
            data['account_number'] = self.account_number
        if hasattr(self, 'account_type'):
            data['account_type'] = self.account_type.value
        if hasattr(self, 'status'):
            data['status'] = self.status.value
        if hasattr(self, 'balance'):
            data['balance'] = float(self.balance)
        if hasattr(self, 'currency'):
            data['currency'] = self.currency
        if hasattr(self, 'interest_rate'):
            data['interest_rate'] = float(self.interest_rate)
        
        return data
