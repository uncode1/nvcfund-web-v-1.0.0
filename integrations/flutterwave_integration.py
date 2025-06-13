from typing import Dict, Any, Optional
import requests
import hmac
import hashlib
import base64
from datetime import datetime
from .base_integration import IntegrationBase
from security.web import WebSecurity
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

class FlutterwaveIntegration(IntegrationBase):
    def __init__(self, config: Dict[str, Any], security: WebSecurity):
        super().__init__(config, security)
        self.base_url = config.get('FLUTTERWAVE_BASE_URL', 'https://api.flutterwave.com')
        self.secret_key = config['FLUTTERWAVE_SECRET_KEY']
        self.public_key = config['FLUTTERWAVE_PUBLIC_KEY']
        self.environment = config.get('FLUTTERWAVE_ENVIRONMENT', 'production')
        
    def initialize(self) -> bool:
        """Initialize Flutterwave integration"""
        try:
            # Test connection
            self._make_request('GET', '/v3/transaction/verify')
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Flutterwave integration: {e}")
            return False
    
    def authenticate(self) -> Dict[str, Any]:
        """Authenticate with Flutterwave"""
        try:
            # Flutterwave uses API keys directly
            return {
                'status': 'success',
                'message': 'Authenticated successfully'
            }
        except Exception as e:
            logger.error(f"Flutterwave authentication failed: {e}")
            raise
    
    def process_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process Flutterwave payment"""
        try:
            url = f"{self.base_url}/v3/payments"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.secret_key}'
            }
            
            response = self._secure_request('POST', url, payment_data)
            return response
            
        except Exception as e:
            logger.error(f"Flutterwave payment processing failed: {e}")
            raise
    
    def refund_payment(self, payment_id: str, amount: float) -> Dict[str, Any]:
        """Refund Flutterwave payment"""
        try:
            url = f"{self.base_url}/v3/transactions/{payment_id}/refund"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.secret_key}'
            }
            
            data = {
                'amount': amount,
                'currency': 'NGN'
            }
            
            response = self._secure_request('POST', url, data)
            return response
            
        except Exception as e:
            logger.error(f"Flutterwave refund failed: {e}")
            raise
    
    def verify_payment(self, payment_id: str) -> Dict[str, Any]:
        """Verify Flutterwave payment"""
        try:
            url = f"{self.base_url}/v3/transactions/{payment_id}/verify"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.secret_key}'
            }
            
            response = self._secure_request('GET', url)
            return response
            
        except Exception as e:
            logger.error(f"Flutterwave verification failed: {e}")
            raise
    
    def get_transaction_details(self, transaction_id: str) -> Dict[str, Any]:
        """Get Flutterwave transaction details"""
        try:
            url = f"{self.base_url}/v3/transactions/{transaction_id}"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.secret_key}'
            }
            
            response = self._secure_request('GET', url)
            return response
            
        except Exception as e:
            logger.error(f"Flutterwave transaction details failed: {e}")
            raise
    
    def _make_request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make Flutterwave API request"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.secret_key}'
        }
        
        response = requests.request(method, url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def _validate_webhook(self, request_data: Dict[str, Any]) -> bool:
        """Validate Flutterwave webhook signature"""
        try:
            # Get webhook data
            event_type = request_data.get('event')
            data = request_data.get('data')
            
            # Validate data
            if not all([event_type, data]):
                return False
                
            # Validate signature
            signature = request_data.get('signature')
            if not signature:
                return False
                
            # Verify signature
            message = f"{event_type}{data['id']}{data['status']}"
            signature_bytes = base64.b64decode(signature)
            
            # Create HMAC
            hmac_hash = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            
            # Compare signatures
            return hmac.compare_digest(hmac_hash, signature_bytes)
            
        except Exception as e:
            logger.error(f"Flutterwave webhook validation failed: {e}")
            return False
    
    def _handle_webhook(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Flutterwave webhook event"""
        try:
            event_type = request_data.get('event')
            data = request_data.get('data')
            
            # Process different event types
            if event_type == 'charge.completed':
                return self._handle_payment_completed(data)
            elif event_type == 'refund.completed':
                return self._handle_refund(data)
            elif event_type == 'charge.failed':
                return self._handle_failed(data)
                
            return {'status': 'success', 'event': event_type}
            
        except Exception as e:
            logger.error(f"Flutterwave webhook handling failed: {e}")
            raise
    
    def _handle_payment_completed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle payment completed event"""
        # Implementation of payment completion handling
        return {'status': 'success', 'payment': data}
    
    def _handle_refund(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle refund event"""
        # Implementation of refund handling
        return {'status': 'success', 'refund': data}
    
    def _handle_failed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle failed payment event"""
        # Implementation of failed payment handling
        return {'status': 'success', 'failed': data}
