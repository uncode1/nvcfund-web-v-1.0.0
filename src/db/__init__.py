from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Enum as SqlEnum
from enum import Enum as PyEnum
from decimal import Decimal

__all__ = ['db', 'BaseModel']

db = SQLAlchemy()

class BaseModel(db.Model):
    __abstract__ = True
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=db.func.current_timestamp())
    updated_at = Column(DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
