from typing import Dict, Any, Optional, Type, List
import logging
from datetime import datetime
from .base_integration import IntegrationBase
from .paypal_integration import PayPalIntegration
from .flutterwave_integration import FlutterwaveIntegration
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

logger = logging.getLogger(__name__)

class IntegrationManager:
    def __init__(self, config: Dict[str, Any], security: WebSecurity):
        self.config = config
        self.security = security
        self.logger = SecurityLogger()
        self.threat_hunter = ThreatHunting(self.logger)
        self.integrations = {}
        self._initialize_integrations()
        
    def _initialize_integrations(self) -> None:
        """Initialize all available integrations"""
        try:
            # Initialize PayPal integration
            if self._is_configured('PAYPAL'):
                self.integrations['paypal'] = PayPalIntegration(self.config, self.security)
                if self.integrations['paypal'].initialize():
                    logger.info("PayPal integration initialized successfully")
                else:
                    logger.warning("Failed to initialize PayPal integration")
                    
            # Initialize Flutterwave integration
            if self._is_configured('FLUTTERWAVE'):
                self.integrations['flutterwave'] = FlutterwaveIntegration(self.config, self.security)
                if self.integrations['flutterwave'].initialize():
                    logger.info("Flutterwave integration initialized successfully")
                else:
                    logger.warning("Failed to initialize Flutterwave integration")
                    
        except Exception as e:
            logger.error(f"Error initializing integrations: {e}")
            raise
    
    def _is_configured(self, service: str) -> bool:
        """Check if service is configured"""
        if service == 'PAYPAL':
            return all([
                self.config.get('PAYPAL_CLIENT_ID'),
                self.config.get('PAYPAL_CLIENT_SECRET')
            ])
            
        if service == 'FLUTTERWAVE':
            return all([
                self.config.get('FLUTTERWAVE_SECRET_KEY'),
                self.config.get('FLUTTERWAVE_PUBLIC_KEY')
            ])
            
        return False
    
    def process_payment(self, service: str, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process payment through specified service"""
        try:
            if service not in self.integrations:
                raise ValueError(f"Service {service} not configured")
                
            integration = self.integrations[service]
            return integration.process_payment(payment_data)
            
        except Exception as e:
            logger.error(f"Error processing payment with {service}: {e}")
            raise
    
    def refund_payment(self, service: str, payment_id: str, amount: float) -> Dict[str, Any]:
        """Refund payment through specified service"""
        try:
            if service not in self.integrations:
                raise ValueError(f"Service {service} not configured")
                
            integration = self.integrations[service]
            return integration.refund_payment(payment_id, amount)
            
        except Exception as e:
            logger.error(f"Error refunding payment with {service}: {e}")
            raise
    
    def verify_payment(self, service: str, payment_id: str) -> Dict[str, Any]:
        """Verify payment status through specified service"""
        try:
            if service not in self.integrations:
                raise ValueError(f"Service {service} not configured")
                
            integration = self.integrations[service]
            return integration.verify_payment(payment_id)
            
        except Exception as e:
            logger.error(f"Error verifying payment with {service}: {e}")
            raise
    
    def get_transaction_details(self, service: str, transaction_id: str) -> Dict[str, Any]:
        """Get transaction details from specified service"""
        try:
            if service not in self.integrations:
                raise ValueError(f"Service {service} not configured")
                
            integration = self.integrations[service]
            return integration.get_transaction_details(transaction_id)
            
        except Exception as e:
            logger.error(f"Error getting transaction details with {service}: {e}")
            raise
    
    def handle_webhook(self, service: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle webhook from specified service"""
        try:
            if service not in self.integrations:
                raise ValueError(f"Service {service} not configured")
                
            integration = self.integrations[service]
            return integration._process_webhook(request_data)
            
        except Exception as e:
            logger.error(f"Error processing webhook with {service}: {e}")
            raise
    
    def monitor_activity(self) -> List[Dict[str, Any]]:
        """Monitor activity across all integrations"""
        activity = []
        
        for service, integration in self.integrations.items():
            try:
                service_activity = integration._monitor_activity()
                activity.extend(service_activity)
                
            except Exception as e:
                logger.error(f"Error monitoring {service} activity: {e}")
                
        return activity
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalies across all integrations"""
        anomalies = []
        
        for service, integration in self.integrations.items():
            try:
                service_anomalies = integration._detect_anomalies()
                anomalies.extend(service_anomalies)
                
            except Exception as e:
                logger.error(f"Error detecting anomalies in {service}: {e}")
                
        return anomalies
    
    def get_supported_services(self) -> List[str]:
        """Get list of supported services"""
        return list(self.integrations.keys())
    
    def get_service_status(self, service: str) -> Dict[str, Any]:
        """Get status of specified service"""
        try:
            if service not in self.integrations:
                raise ValueError(f"Service {service} not configured")
                
            integration = self.integrations[service]
            return {
                'service': service,
                'status': 'active',
                'last_checked': datetime.now().isoformat(),
                'details': integration.authenticate()
            }
            
        except Exception as e:
            logger.error(f"Error getting status for {service}: {e}")
            return {
                'service': service,
                'status': 'error',
                'error': str(e)
            }
