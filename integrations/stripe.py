from .base import IntegrationBase
import stripe
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class Stripe(IntegrationBase):
    """Stripe payment integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.stripe = None
        self.webhook_secret = config.get('webhook_secret')
    
    def initialize(self) -> bool:
        """Initialize Stripe integration"""
        try:
            stripe.api_key = self.config['api_key']
            self.stripe = stripe
            self.is_active = True
            return True
        except Exception as e:
            self.error(f"Initialization failed: {str(e)}")
            return False
    
    def authenticate(self) -> bool:
        """Authenticate with Stripe"""
        try:
            # Verify API key by making a test request
            self.stripe.Account.retrieve()
            return True
        except Exception as e:
            self.error(f"Authentication failed: {str(e)}")
            return False
    
    def sync_data(self) -> Dict[str, Any]:
        """Sync data from Stripe"""
        try:
            # Get recent charges
            charges = self.stripe.Charge.list(limit=100)
            
            # Get subscriptions
            subscriptions = self.stripe.Subscription.list(limit=100)
            
            return {
                'charges': charges.data,
                'subscriptions': subscriptions.data
            }
        except Exception as e:
            self.error(f"Sync failed: {str(e)}")
            raise
    
    def process_webhook(self, data: Dict[str, Any]) -> bool:
        """Process Stripe webhook events"""
        try:
            event = stripe.Webhook.construct_event(
                payload=data,
                sig_header=self.webhook_secret,
                secret=self.config['webhook_secret']
            )
            
            # Handle different event types
            if event.type == 'charge.succeeded':
                self.info("Charge succeeded")
                # Process successful charge
                
            elif event.type == 'charge.failed':
                self.warning("Charge failed")
                # Process failed charge
                
            return True
        except stripe.error.SignatureVerificationError:
            self.error("Invalid webhook signature")
            return False
        except Exception as e:
            self.error(f"Webhook processing failed: {str(e)}")
            return False
    
    def create_payment_intent(self, amount: int, currency: str) -> Dict[str, Any]:
        """Create a payment intent"""
        try:
            intent = self.stripe.PaymentIntent.create(
                amount=amount,
                currency=currency,
                automatic_payment_methods={'enabled': True}
            )
            return intent
        except Exception as e:
            self.error(f"Failed to create payment intent: {str(e)}")
            raise
    
    def refund_payment(self, payment_id: str, amount: Optional[int] = None) -> Dict[str, Any]:
        """Refund a payment"""
        try:
            refund = self.stripe.Refund.create(
                payment_intent=payment_id,
                amount=amount
            )
            return refund
        except Exception as e:
            self.error(f"Failed to refund payment: {str(e)}")
            raise
