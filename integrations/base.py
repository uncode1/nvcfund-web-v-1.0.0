from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class IntegrationBase(ABC):
    """Base class for all integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.is_active = False
        self.last_sync = None
        
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the integration"""
        pass
    
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the external service"""
        pass
    
    @abstractmethod
    def sync_data(self) -> Dict[str, Any]:
        """Synchronize data from the external service"""
        pass
    
    @abstractmethod
    def process_webhook(self, data: Dict[str, Any]) -> bool:
        """Process incoming webhook data"""
        pass
    
    def health_check(self) -> Dict[str, Any]:
        """Check integration health"""
        return {
            'name': self.name,
            'status': 'active' if self.is_active else 'inactive',
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'errors': []
        }
    
    def log(self, message: str, level: str = 'info'):
        """Log messages with integration context"""
        log_method = getattr(logger, level.lower())
        log_method(f"[{self.name}] {message}")
    
    def error(self, message: str):
        """Log error with integration context"""
        self.log(message, 'error')
    
    def warning(self, message: str):
        """Log warning with integration context"""
        self.log(message, 'warning')
    
    def info(self, message: str):
        """Log info with integration context"""
        self.log(message, 'info')
    
    def debug(self, message: str):
        """Log debug with integration context"""
        self.log(message, 'debug')
