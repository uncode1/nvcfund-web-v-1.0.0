from typing import Dict, Type, Any
from .base import IntegrationBase
import importlib
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class IntegrationManager:
    def __init__(self):
        self.integrations: Dict[str, IntegrationBase] = {}
        self.active_integrations: Dict[str, IntegrationBase] = {}
        self.last_health_check: Optional[datetime] = None
    
    def register_integration(self, name: str, integration_class: Type[IntegrationBase]):
        """Register a new integration"""
        self.integrations[name] = integration_class
        logger.info(f"Registered integration: {name}")
    
    def initialize_all(self, config: Dict[str, Any]) -> Dict[str, bool]:
        """Initialize all registered integrations"""
        results = {}
        for name, integration_class in self.integrations.items():
            if name in config:
                integration = integration_class(config[name])
                success = integration.initialize()
                if success:
                    self.active_integrations[name] = integration
                results[name] = success
        return results
    
    def get_integration(self, name: str) -> Optional[IntegrationBase]:
        """Get an initialized integration"""
        return self.active_integrations.get(name)
    
    def sync_all(self) -> Dict[str, Any]:
        """Sync data from all active integrations"""
        results = {}
        for name, integration in self.active_integrations.items():
            try:
                data = integration.sync_data()
                integration.last_sync = datetime.utcnow()
                results[name] = {
                    'success': True,
                    'data': data
                }
            except Exception as e:
                integration.error(f"Sync failed: {str(e)}")
                results[name] = {
                    'success': False,
                    'error': str(e)
                }
        return results
    
    def process_webhook(self, integration_name: str, data: Dict[str, Any]) -> bool:
        """Process incoming webhook data"""
        integration = self.get_integration(integration_name)
        if not integration:
            return False
            
        try:
            return integration.process_webhook(data)
        except Exception as e:
            integration.error(f"Webhook processing failed: {str(e)}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Check health of all integrations"""
        results = {}
        self.last_health_check = datetime.utcnow()
        
        for name, integration in self.active_integrations.items():
            try:
                results[name] = integration.health_check()
            except Exception as e:
                results[name] = {
                    'name': name,
                    'status': 'error',
                    'error': str(e)
                }
        
        return results
    
    def load_integration(self, name: str) -> Optional[Type[IntegrationBase]]:
        """Dynamically load an integration module"""
        try:
            module = importlib.import_module(f'integrations.{name.lower()}')
            integration_class = getattr(module, name)
            return integration_class
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to load integration {name}: {str(e)}")
            return None
    
    def reload_integration(self, name: str) -> bool:
        """Reload an integration module"""
        integration_class = self.load_integration(name)
        if integration_class:
            self.register_integration(name, integration_class)
            return True
        return False
