"""Payment processing service with secure coding practices."""

import logging
import secrets
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from ..models import (
    db, Transaction, TransactionType, TransactionStatus, PaymentGateway,
    User, StablecoinAccount, LedgerEntry
)
from ..utils.security_utils import sanitize_input, validate_amount


logger = logging.getLogger(__name__)


class PaymentServiceError(Exception):
    """Custom exception for payment service errors."""
    pass


class PaymentService:
    """Secure payment processing service."""
    
    @staticmethod
    def validate_payment_data(payment_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate payment data with security checks.
        
        Args:
            payment_data: Dictionary containing payment information
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Required fields validation
        required_fields = ['amount', 'currency', 'recipient_account']
        for field in required_fields:
            if field not in payment_data or not payment_data[field]:
                errors.append(f"Missing required field: {field}")
        
        # Amount validation
        try:
            amount = validate_amount(payment_data.get('amount', 0))
            if amount <= 0:
                errors.append("Amount must be positive")
            if amount > Decimal('1000000'):  # Max transaction limit
                errors.append("Amount exceeds maximum transaction limit")
        except (ValueError, TypeError):
            errors.append("Invalid amount format")
        
        # Currency validation
        currency = sanitize_input(payment_data.get('currency', ''))
        if currency not in ['USD', 'EUR', 'GBP', 'NVCT', 'AFD1']:
            errors.append("Unsupported currency")
        
        # Recipient account validation
        recipient_account = sanitize_input(payment_data.get('recipient_account', ''))
        if len(recipient_account) < 5 or len(recipient_account) > 64:
            errors.append("Invalid recipient account format")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def create_payment(
        user_id: int,
        payment_data: Dict,
        gateway_id: Optional[int] = None
    ) -> Tuple[bool, str, Optional[Transaction]]:
        """
        Create a secure payment transaction.
        
        Args:
            user_id: ID of the user making the payment
            payment_data: Payment details
            gateway_id: Optional payment gateway ID
            
        Returns:
            Tuple of (success, message, transaction)
        """
        try:
            # Validate input data
            is_valid, errors = PaymentService.validate_payment_data(payment_data)
            if not is_valid:
                return False, "; ".join(errors), None
            
            # Verify user exists and is active
            user = User.query.filter_by(id=user_id, is_active=True).first()
            if not user:
                logger.warning(f"Payment attempt by invalid user ID: {user_id}")
                return False, "Invalid user", None
            
            # Create transaction with secure ID
            transaction_id = secrets.token_hex(16)
            
            transaction = Transaction(
                transaction_id=transaction_id,
                user_id=user_id,
                amount=float(validate_amount(payment_data['amount'])),
                currency=sanitize_input(payment_data['currency']),
                transaction_type=TransactionType.PAYMENT,
                status=TransactionStatus.PENDING,
                description=sanitize_input(payment_data.get('description', '')),
                recipient_name=sanitize_input(payment_data.get('recipient_name', '')),
                recipient_account=sanitize_input(payment_data['recipient_account']),
                recipient_address=sanitize_input(payment_data.get('recipient_address', '')),
                gateway_id=gateway_id
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            logger.info(f"Payment created: {transaction_id} for user {user_id}")
            return True, "Payment created successfully", transaction
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating payment: {str(e)}")
            return False, "Database error occurred", None
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error creating payment: {str(e)}")
            return False, "An unexpected error occurred", None
    
    @staticmethod
    def process_stablecoin_transfer(
        from_user_id: int,
        to_account_number: str,
        amount: float,
        description: str = None
    ) -> Tuple[bool, str, Optional[Transaction]]:
        """
        Process a secure stablecoin transfer.
        
        Args:
            from_user_id: ID of the sending user
            to_account_number: Recipient account number
            amount: Transfer amount
            description: Optional transfer description
            
        Returns:
            Tuple of (success, message, transaction)
        """
        try:
            # Validate amount
            amount = float(validate_amount(amount))
            if amount <= 0:
                return False, "Invalid transfer amount", None
            
            # Get sender's stablecoin account
            from_account = StablecoinAccount.query.filter_by(
                user_id=from_user_id,
                is_active=True
            ).first()
            
            if not from_account:
                return False, "Sender account not found", None
            
            # Check sufficient balance
            if from_account.balance < amount:
                logger.warning(f"Insufficient funds for transfer: {from_user_id}")
                return False, "Insufficient funds", None
            
            # Get recipient account
            to_account = StablecoinAccount.query.filter_by(
                account_number=sanitize_input(to_account_number),
                is_active=True
            ).first()
            
            if not to_account:
                return False, "Recipient account not found", None
            
            # Prevent self-transfer
            if from_account.id == to_account.id:
                return False, "Cannot transfer to same account", None
            
            # Process the transfer
            transaction = from_account.transfer(
                to_account,
                amount,
                sanitize_input(description) if description else None
            )
            
            db.session.commit()
            
            logger.info(f"Stablecoin transfer completed: {transaction.transaction_id}")
            return True, "Transfer completed successfully", transaction
            
        except ValueError as e:
            db.session.rollback()
            logger.error(f"Validation error in stablecoin transfer: {str(e)}")
            return False, str(e), None
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error in stablecoin transfer: {str(e)}")
            return False, "Database error occurred", None
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error in stablecoin transfer: {str(e)}")
            return False, "An unexpected error occurred", None
    
    @staticmethod
    def get_user_transactions(
        user_id: int,
        limit: int = 50,
        offset: int = 0,
        transaction_type: Optional[TransactionType] = None
    ) -> List[Transaction]:
        """
        Get user transactions with pagination and filtering.
        
        Args:
            user_id: User ID
            limit: Maximum number of transactions to return
            offset: Number of transactions to skip
            transaction_type: Optional filter by transaction type
            
        Returns:
            List of transactions
        """
        try:
            # Validate and sanitize inputs
            limit = min(max(int(limit), 1), 100)  # Limit between 1-100
            offset = max(int(offset), 0)
            
            query = Transaction.query.filter_by(user_id=user_id)
            
            if transaction_type:
                query = query.filter_by(transaction_type=transaction_type)
            
            transactions = query.order_by(Transaction.created_at.desc())\
                              .limit(limit)\
                              .offset(offset)\
                              .all()
            
            return transactions
            
        except Exception as e:
            logger.error(f"Error retrieving user transactions: {str(e)}")
            return []
    
    @staticmethod
    def get_transaction_by_id(
        transaction_id: str,
        user_id: Optional[int] = None
    ) -> Optional[Transaction]:
        """
        Get transaction by ID with optional user verification.
        
        Args:
            transaction_id: Transaction ID
            user_id: Optional user ID for ownership verification
            
        Returns:
            Transaction object or None
        """
        try:
            transaction_id = sanitize_input(transaction_id)
            
            query = Transaction.query.filter_by(transaction_id=transaction_id)
            
            if user_id:
                query = query.filter_by(user_id=user_id)
            
            return query.first()
            
        except Exception as e:
            logger.error(f"Error retrieving transaction: {str(e)}")
            return None
    
    @staticmethod
    def update_transaction_status(
        transaction_id: str,
        new_status: TransactionStatus,
        user_id: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Update transaction status with security checks.
        
        Args:
            transaction_id: Transaction ID
            new_status: New status to set
            user_id: Optional user ID for authorization
            
        Returns:
            Tuple of (success, message)
        """
        try:
            transaction = PaymentService.get_transaction_by_id(transaction_id, user_id)
            
            if not transaction:
                return False, "Transaction not found"
            
            # Validate status transition
            valid_transitions = {
                TransactionStatus.PENDING: [
                    TransactionStatus.PROCESSING,
                    TransactionStatus.CANCELLED,
                    TransactionStatus.REJECTED
                ],
                TransactionStatus.PROCESSING: [
                    TransactionStatus.COMPLETED,
                    TransactionStatus.FAILED
                ],
                TransactionStatus.COMPLETED: [],  # Final state
                TransactionStatus.FAILED: [TransactionStatus.PENDING],  # Allow retry
                TransactionStatus.CANCELLED: [],  # Final state
                TransactionStatus.REJECTED: []  # Final state
            }
            
            if new_status not in valid_transitions.get(transaction.status, []):
                return False, f"Invalid status transition from {transaction.status.value} to {new_status.value}"
            
            transaction.status = new_status
            transaction.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            logger.info(f"Transaction {transaction_id} status updated to {new_status.value}")
            return True, "Status updated successfully"
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating transaction status: {str(e)}")
            return False, "Database error occurred"
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error updating transaction status: {str(e)}")
            return False, "An unexpected error occurred"