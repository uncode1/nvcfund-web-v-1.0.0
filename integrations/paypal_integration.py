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

class PayPalIntegration(IntegrationBase):
    def __init__(self, config: Dict[str, Any], security: WebSecurity):
        super().__init__(config, security)
        self.base_url = config.get('PAYPAL_BASE_URL', 'https://api.paypal.com')
        self.client_id = config['PAYPAL_CLIENT_ID']
        self.client_secret = config['PAYPAL_CLIENT_SECRET']
        self.access_token = None
        self.token_expires = None
        
    def initialize(self) -> bool:
        """Initialize PayPal integration"""
        try:
            self.authenticate()
            return True
        except Exception as e:
            logger.error(f"Failed to initialize PayPal integration: {e}")
            return False
    
    def authenticate(self) -> Dict[str, Any]:
        """Authenticate with PayPal"""
        try:
            auth_url = f"{self.base_url}/v1/oauth2/token"
            auth = (self.client_id, self.client_secret)
            data = {
                'grant_type': 'client_credentials'
            }
            
            response = requests.post(auth_url, auth=auth, data=data)
            response.raise_for_status()
            
            auth_data = response.json()
            self.access_token = auth_data['access_token']
            self.token_expires = datetime.now() + timedelta(seconds=auth_data['expires_in'])
            
            return auth_data
            
        except Exception as e:
            logger.error(f"PayPal authentication failed: {e}")
            raise
    
    def process_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process PayPal payment"""
        try:
            if not self._check_token_validity():
                self.authenticate()
                
            url = f"{self.base_url}/v2/checkout/orders"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = self._secure_request('POST', url, payment_data)
            return response
            
        except Exception as e:
            logger.error(f"PayPal payment processing failed: {e}")
            raise
    
    def refund_payment(self, payment_id: str, amount: float) -> Dict[str, Any]:
        """Refund PayPal payment"""
        try:
            if not self._check_token_validity():
                self.authenticate()
                
            url = f"{self.base_url}/v2/payments/captures/{payment_id}/refund"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.access_token}'
            }
            
            data = {
                'amount': {
                    'value': str(amount),
                    'currency_code': 'USD'
                }
            }
            
            response = self._secure_request('POST', url, data)
            return response
            
        except Exception as e:
            logger.error(f"PayPal refund failed: {e}")
            raise
    
    def verify_payment(self, payment_id: str) -> Dict[str, Any]:
        """Verify PayPal payment"""
        try:
            if not self._check_token_validity():
                self.authenticate()
                
            url = f"{self.base_url}/v2/checkout/orders/{payment_id}"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = self._secure_request('GET', url)
            return response
            
        except Exception as e:
            logger.error(f"PayPal verification failed: {e}")
            raise
    
    def get_transaction_details(self, transaction_id: str) -> Dict[str, Any]:
        """Get PayPal transaction details"""
        try:
            if not self._check_token_validity():
                self.authenticate()
                
            url = f"{self.base_url}/v2/payments/captures/{transaction_id}"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = self._secure_request('GET', url)
            return response
            
        except Exception as e:
            logger.error(f"PayPal transaction details failed: {e}")
            raise
    
    def _make_request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make PayPal API request"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        
        response = requests.request(method, url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def _validate_webhook(self, request_data: Dict[str, Any]) -> bool:
        """Validate PayPal webhook signature"""
        try:
            # Get webhook data
            webhook_id = request_data.get('id')
            event_type = request_data.get('event_type')
            resource = request_data.get('resource')
            
            # Validate data
            if not all([webhook_id, event_type, resource]):
                return False
                
            # Validate signature
            signature = request_data.get('paypal-signature')
            if not signature:
                return False
                
            # Verify signature
            message = f"{webhook_id}{event_type}{resource}"
            signature_bytes = base64.b64decode(signature)
            
            # Create HMAC
            hmac_hash = hmac.new(
                self.client_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            
            # Compare signatures
            return hmac.compare_digest(hmac_hash, signature_bytes)
            
        except Exception as e:
            logger.error(f"PayPal webhook validation failed: {e}")
            return False
    
    def _handle_webhook(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle PayPal webhook event"""
        try:
            event_type = request_data.get('event_type')
            resource = request_data.get('resource')
            
            # Process different event types
            if event_type == 'PAYMENT.SALE.COMPLETED':
                return self._handle_payment_completed(resource)
            elif event_type == 'PAYMENT.SALE.REFUNDED':
                return self._handle_refund(resource)
            elif event_type == 'PAYMENT.SALE.DENIED':
                return self._handle_denied(resource)
                
            return {'status': 'success', 'event': event_type}
            
        except Exception as e:
            logger.error(f"PayPal webhook handling failed: {e}")
            raise
    
    def _handle_payment_completed(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Handle payment completed event"""
        # Implementation of payment completion handling
        return {'status': 'success', 'payment': resource}
    
    def _handle_refund(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Handle refund event"""
        # Implementation of refund handling
        return {'status': 'success', 'refund': resource}
    
    def _handle_denied(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Handle denied payment event"""
        # Implementation of denied payment handling
        return {'status': 'success', 'denied': resource}
    
    def _check_token_validity(self) -> bool:
        """Check if access token is still valid"""
        if not self.access_token:
            return False
            
        if not self.token_expires:
            return False
            
        return datetime.now() < self.token_expires
