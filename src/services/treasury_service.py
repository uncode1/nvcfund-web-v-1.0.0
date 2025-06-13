"""Treasury management service with secure operations."""

import logging
import secrets
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import and_, or_

from ..models import (
    db, TreasuryAccount, TreasuryInvestment, TreasuryAccountType,
    InvestmentType, InvestmentStatus, FinancialInstitution,
    Transaction, TransactionType, TransactionStatus
)
from ..utils.security_utils import sanitize_input, validate_amount


logger = logging.getLogger(__name__)


class TreasuryServiceError(Exception):
    """Custom exception for treasury service errors."""
    pass


class TreasuryService:
    """Secure treasury management service."""
    
    @staticmethod
    def create_treasury_account(
        name: str,
        account_type: TreasuryAccountType,
        institution_id: Optional[int] = None,
        initial_balance: float = 0.0,
        currency: str = "USD",
        **kwargs
    ) -> Tuple[bool, str, Optional[TreasuryAccount]]:
        """
        Create a new treasury account with validation.
        
        Args:
            name: Account name
            account_type: Type of treasury account
            institution_id: Optional financial institution ID
            initial_balance: Initial account balance
            currency: Account currency
            **kwargs: Additional account parameters
            
        Returns:
            Tuple of (success, message, account)
        """
        try:
            # Validate inputs
            name = sanitize_input(name)
            if not name or len(name) < 3:
                return False, "Account name must be at least 3 characters", None
            
            currency = sanitize_input(currency).upper()
            if currency not in ['USD', 'EUR', 'GBP', 'JPY', 'CHF']:
                return False, "Unsupported currency", None
            
            initial_balance = float(validate_amount(initial_balance))
            if initial_balance < 0:
                return False, "Initial balance cannot be negative", None
            
            # Verify institution if provided
            if institution_id:
                institution = FinancialInstitution.query.filter_by(
                    id=institution_id,
                    is_active=True
                ).first()
                if not institution:
                    return False, "Invalid financial institution", None
            
            # Create account
            account = TreasuryAccount(
                name=name,
                account_type=account_type,
                institution_id=institution_id,
                current_balance=initial_balance,
                available_balance=initial_balance,
                currency=currency,
                description=sanitize_input(kwargs.get('description', '')),
                target_balance=kwargs.get('target_balance'),
                minimum_balance=kwargs.get('minimum_balance', 0.0),
                maximum_balance=kwargs.get('maximum_balance'),
                organization_id=kwargs.get('organization_id')
            )
            
            db.session.add(account)
            db.session.commit()
            
            logger.info(f"Treasury account created: {account.name} (ID: {account.id})")
            return True, "Treasury account created successfully", account
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating treasury account: {str(e)}")
            return False, "Database error occurred", None
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error creating treasury account: {str(e)}")
            return False, "An unexpected error occurred", None
    
    @staticmethod
    def transfer_funds(
        from_account_id: int,
        to_account_id: int,
        amount: float,
        description: str = None,
        user_id: Optional[int] = None
    ) -> Tuple[bool, str, Optional[Transaction]]:
        """
        Transfer funds between treasury accounts.
        
        Args:
            from_account_id: Source account ID
            to_account_id: Destination account ID
            amount: Transfer amount
            description: Optional transfer description
            user_id: User initiating the transfer
            
        Returns:
            Tuple of (success, message, transaction)
        """
        try:
            # Validate amount
            amount = float(validate_amount(amount))
            if amount <= 0:
                return False, "Transfer amount must be positive", None
            
            # Get accounts
            from_account = TreasuryAccount.query.filter_by(
                id=from_account_id,
                is_active=True
            ).first()
            
            to_account = TreasuryAccount.query.filter_by(
                id=to_account_id,
                is_active=True
            ).first()
            
            if not from_account:
                return False, "Source account not found", None
            
            if not to_account:
                return False, "Destination account not found", None
            
            # Prevent self-transfer
            if from_account_id == to_account_id:
                return False, "Cannot transfer to same account", None
            
            # Check sufficient funds
            if from_account.available_balance < amount:
                logger.warning(f"Insufficient funds for treasury transfer: {from_account_id}")
                return False, "Insufficient funds", None
            
            # Check account limits
            if not from_account.is_within_limits():
                return False, "Source account balance limits violated", None
            
            # Currency compatibility check
            if from_account.currency != to_account.currency:
                return False, "Currency mismatch between accounts", None
            
            # Create transaction record
            transaction_id = secrets.token_hex(16)
            
            transaction = Transaction(
                transaction_id=transaction_id,
                user_id=user_id,
                amount=amount,
                currency=from_account.currency,
                transaction_type=TransactionType.TREASURY_TRANSFER,
                status=TransactionStatus.COMPLETED,
                description=sanitize_input(description) if description else f"Transfer from {from_account.name} to {to_account.name}",
                recipient_name=to_account.name,
                recipient_account=str(to_account.id)
            )
            
            # Update account balances
            from_account.current_balance -= amount
            from_account.available_balance -= amount
            from_account.updated_at = datetime.utcnow()
            
            to_account.current_balance += amount
            to_account.available_balance += amount
            to_account.updated_at = datetime.utcnow()
            
            db.session.add(transaction)
            db.session.commit()
            
            logger.info(f"Treasury transfer completed: {transaction_id}")
            return True, "Transfer completed successfully", transaction
            
        except ValueError as e:
            db.session.rollback()
            logger.error(f"Validation error in treasury transfer: {str(e)}")
            return False, str(e), None
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error in treasury transfer: {str(e)}")
            return False, "Database error occurred", None
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error in treasury transfer: {str(e)}")
            return False, "An unexpected error occurred", None
    
    @staticmethod
    def create_investment(
        account_id: int,
        investment_type: InvestmentType,
        amount: float,
        interest_rate: float,
        start_date: datetime,
        maturity_date: datetime,
        institution_id: Optional[int] = None,
        description: str = None
    ) -> Tuple[bool, str, Optional[TreasuryInvestment]]:
        """
        Create a new treasury investment.
        
        Args:
            account_id: Treasury account ID
            investment_type: Type of investment
            amount: Investment amount
            interest_rate: Annual interest rate (percentage)
            start_date: Investment start date
            maturity_date: Investment maturity date
            institution_id: Optional institution ID
            description: Optional description
            
        Returns:
            Tuple of (success, message, investment)
        """
        try:
            # Validate inputs
            amount = float(validate_amount(amount))
            if amount <= 0:
                return False, "Investment amount must be positive", None
            
            if interest_rate < 0 or interest_rate > 100:
                return False, "Interest rate must be between 0 and 100", None
            
            if maturity_date <= start_date:
                return False, "Maturity date must be after start date", None
            
            # Get treasury account
            account = TreasuryAccount.query.filter_by(
                id=account_id,
                is_active=True
            ).first()
            
            if not account:
                return False, "Treasury account not found", None
            
            # Check sufficient funds
            if account.available_balance < amount:
                return False, "Insufficient funds for investment", None
            
            # Verify institution if provided
            if institution_id:
                institution = FinancialInstitution.query.filter_by(
                    id=institution_id,
                    is_active=True
                ).first()
                if not institution:
                    return False, "Invalid financial institution", None
            
            # Generate investment ID
            investment_id = f"INV-{secrets.token_hex(8).upper()}"
            
            # Create investment
            investment = TreasuryInvestment(
                investment_id=investment_id,
                account_id=account_id,
                investment_type=investment_type,
                amount=amount,
                currency=account.currency,
                interest_rate=interest_rate,
                start_date=start_date,
                maturity_date=maturity_date,
                institution_id=institution_id,
                status=InvestmentStatus.PENDING,
                description=sanitize_input(description) if description else None
            )
            
            # Reserve funds in account
            account.available_balance -= amount
            account.updated_at = datetime.utcnow()
            
            db.session.add(investment)
            db.session.commit()
            
            logger.info(f"Treasury investment created: {investment_id}")
            return True, "Investment created successfully", investment
            
        except ValueError as e:
            db.session.rollback()
            logger.error(f"Validation error creating investment: {str(e)}")
            return False, str(e), None
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating investment: {str(e)}")
            return False, "Database error occurred", None
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error creating investment: {str(e)}")
            return False, "An unexpected error occurred", None
    
    @staticmethod
    def get_account_summary(account_id: int) -> Optional[Dict]:
        """
        Get comprehensive account summary.
        
        Args:
            account_id: Treasury account ID
            
        Returns:
            Account summary dictionary or None
        """
        try:
            account = TreasuryAccount.query.filter_by(
                id=account_id,
                is_active=True
            ).first()
            
            if not account:
                return None
            
            # Get recent transactions
            recent_transactions = Transaction.query.filter(
                and_(
                    or_(
                        Transaction.recipient_account == str(account_id),
                        Transaction.user_id == account_id  # Simplified for demo
                    ),
                    Transaction.transaction_type.in_([
                        TransactionType.TREASURY_TRANSFER,
                        TransactionType.TREASURY_INVESTMENT,
                        TransactionType.TREASURY_FUNDING
                    ])
                )
            ).order_by(Transaction.created_at.desc()).limit(10).all()
            
            # Get active investments
            active_investments = TreasuryInvestment.query.filter_by(
                account_id=account_id,
                status=InvestmentStatus.ACTIVE
            ).all()
            
            # Calculate investment value
            total_investment_value = sum(
                inv.calculate_maturity_value() for inv in active_investments
            )
            
            return {
                'account': {
                    'id': account.id,
                    'name': account.name,
                    'type': account.account_type.value,
                    'currency': account.currency,
                    'current_balance': account.current_balance,
                    'available_balance': account.available_balance,
                    'target_balance': account.target_balance,
                    'minimum_balance': account.minimum_balance,
                    'maximum_balance': account.maximum_balance,
                    'is_within_limits': account.is_within_limits(),
                    'last_reconciled': account.last_reconciled.isoformat() if account.last_reconciled else None
                },
                'investments': {
                    'count': len(active_investments),
                    'total_value': total_investment_value,
                    'active_investments': [
                        {
                            'id': inv.investment_id,
                            'type': inv.investment_type.value,
                            'amount': inv.amount,
                            'interest_rate': inv.interest_rate,
                            'maturity_date': inv.maturity_date.isoformat(),
                            'maturity_value': inv.calculate_maturity_value()
                        }
                        for inv in active_investments
                    ]
                },
                'recent_transactions': [
                    {
                        'id': tx.transaction_id,
                        'type': tx.transaction_type.value,
                        'amount': tx.amount,
                        'currency': tx.currency,
                        'status': tx.status.value,
                        'description': tx.description,
                        'created_at': tx.created_at.isoformat()
                    }
                    for tx in recent_transactions
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting account summary: {str(e)}")
            return None
    
    @staticmethod
    def get_portfolio_overview(organization_id: Optional[int] = None) -> Dict:
        """
        Get treasury portfolio overview.
        
        Args:
            organization_id: Optional organization filter
            
        Returns:
            Portfolio overview dictionary
        """
        try:
            # Build query
            query = TreasuryAccount.query.filter_by(is_active=True)
            if organization_id:
                query = query.filter_by(organization_id=organization_id)
            
            accounts = query.all()
            
            # Calculate totals by currency
            currency_totals = {}
            account_types = {}
            
            for account in accounts:
                currency = account.currency
                account_type = account.account_type.value
                
                if currency not in currency_totals:
                    currency_totals[currency] = {
                        'current_balance': 0,
                        'available_balance': 0,
                        'account_count': 0
                    }
                
                if account_type not in account_types:
                    account_types[account_type] = {
                        'balance': 0,
                        'count': 0
                    }
                
                currency_totals[currency]['current_balance'] += account.current_balance
                currency_totals[currency]['available_balance'] += account.available_balance
                currency_totals[currency]['account_count'] += 1
                
                account_types[account_type]['balance'] += account.current_balance
                account_types[account_type]['count'] += 1
            
            # Get investment summary
            investments = TreasuryInvestment.query.filter_by(
                status=InvestmentStatus.ACTIVE
            ).all()
            
            investment_summary = {
                'total_count': len(investments),
                'total_value': sum(inv.amount for inv in investments),
                'projected_value': sum(inv.calculate_maturity_value() for inv in investments),
                'by_type': {}
            }
            
            for inv in investments:
                inv_type = inv.investment_type.value
                if inv_type not in investment_summary['by_type']:
                    investment_summary['by_type'][inv_type] = {
                        'count': 0,
                        'value': 0,
                        'projected_value': 0
                    }
                
                investment_summary['by_type'][inv_type]['count'] += 1
                investment_summary['by_type'][inv_type]['value'] += inv.amount
                investment_summary['by_type'][inv_type]['projected_value'] += inv.calculate_maturity_value()
            
            return {
                'summary': {
                    'total_accounts': len(accounts),
                    'currency_breakdown': currency_totals,
                    'account_type_breakdown': account_types
                },
                'investments': investment_summary,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting portfolio overview: {str(e)}")
            return {
                'error': 'Failed to generate portfolio overview',
                'generated_at': datetime.utcnow().isoformat()
            }