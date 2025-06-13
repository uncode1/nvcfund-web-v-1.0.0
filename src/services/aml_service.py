"""
Anti-Money Laundering (AML) Service Module

This module provides comprehensive AML compliance functionality including:
- Transaction monitoring and analysis
- Risk scoring and assessment
- Suspicious activity detection
- Regulatory reporting
- Customer due diligence (CDD)
- Enhanced due diligence (EDD)
- Sanctions screening
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from decimal import Decimal
from dataclasses import dataclass
from enum import Enum

from flask import request, current_app
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import SQLAlchemyError

from ..models import (
    db, User, Transaction, TransactionType, TransactionStatus,
    StablecoinAccount, WireTransfer
)
from ..utils.security_utils import sanitize_input, log_security_event
from .logging_service import LoggingService


logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level enumeration for AML assessments."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AMLAlertType(Enum):
    """Types of AML alerts that can be generated."""
    LARGE_TRANSACTION = "large_transaction"
    RAPID_TRANSACTIONS = "rapid_transactions"
    UNUSUAL_PATTERN = "unusual_pattern"
    SANCTIONS_MATCH = "sanctions_match"
    HIGH_RISK_COUNTRY = "high_risk_country"
    STRUCTURING = "structuring"
    ROUND_DOLLAR = "round_dollar"
    VELOCITY_CHECK = "velocity_check"
    DORMANT_ACCOUNT = "dormant_account"
    CROSS_BORDER = "cross_border"


@dataclass
class AMLAlert:
    """Data class for AML alert information."""
    alert_type: AMLAlertType
    risk_level: RiskLevel
    user_id: int
    transaction_id: Optional[str]
    description: str
    score: float
    metadata: Dict[str, Any]
    created_at: datetime


@dataclass
class RiskAssessment:
    """Data class for risk assessment results."""
    user_id: int
    overall_risk: RiskLevel
    risk_score: float
    factors: List[str]
    recommendations: List[str]
    assessed_at: datetime


class AMLService:
    """
    Comprehensive Anti-Money Laundering service.
    
    This service provides real-time transaction monitoring, risk assessment,
    and compliance reporting functionality to meet regulatory requirements.
    """
    
    # Configuration constants
    LARGE_TRANSACTION_THRESHOLD = Decimal('10000.00')
    RAPID_TRANSACTION_COUNT = 5
    RAPID_TRANSACTION_WINDOW = timedelta(hours=1)
    VELOCITY_DAILY_LIMIT = Decimal('50000.00')
    STRUCTURING_THRESHOLD = Decimal('9500.00')
    
    # High-risk countries (simplified list)
    HIGH_RISK_COUNTRIES = {
        'AF', 'IR', 'KP', 'SY', 'MM', 'BY', 'CU', 'IQ', 'LB', 'LY',
        'SO', 'SS', 'SD', 'VE', 'YE', 'ZW'
    }
    
    # Sanctions list (simplified - in production, integrate with OFAC/EU lists)
    SANCTIONS_LIST = {
        'individuals': set(),
        'entities': set(),
        'addresses': set()
    }

    @staticmethod
    def analyze_transaction(transaction: Transaction) -> Tuple[List[AMLAlert], RiskLevel]:
        """
        Analyze a transaction for AML compliance.
        
        Args:
            transaction: Transaction object to analyze
            
        Returns:
            Tuple of (alerts_list, overall_risk_level)
        """
        alerts = []
        max_risk = RiskLevel.LOW
        
        try:
            # Get request context for logging
            request_info = AMLService._get_request_info()
            
            # Large transaction check
            if transaction.amount >= AMLService.LARGE_TRANSACTION_THRESHOLD:
                alert = AMLAlert(
                    alert_type=AMLAlertType.LARGE_TRANSACTION,
                    risk_level=RiskLevel.MEDIUM,
                    user_id=transaction.user_id,
                    transaction_id=transaction.transaction_id,
                    description=f"Large transaction: {transaction.amount} {transaction.currency}",
                    score=0.6,
                    metadata={
                        'amount': float(transaction.amount),
                        'currency': transaction.currency,
                        'threshold': float(AMLService.LARGE_TRANSACTION_THRESHOLD),
                        'request_info': request_info
                    },
                    created_at=datetime.utcnow()
                )
                alerts.append(alert)
                max_risk = max(max_risk, RiskLevel.MEDIUM, key=lambda x: x.value)
            
            # Rapid transactions check
            rapid_alerts = AMLService._check_rapid_transactions(transaction)
            alerts.extend(rapid_alerts)
            if rapid_alerts:
                max_risk = max(max_risk, RiskLevel.HIGH, key=lambda x: x.value)
            
            # Structuring check
            structuring_alert = AMLService._check_structuring(transaction)
            if structuring_alert:
                alerts.append(structuring_alert)
                max_risk = max(max_risk, RiskLevel.HIGH, key=lambda x: x.value)
            
            # Round dollar check
            round_dollar_alert = AMLService._check_round_dollar(transaction)
            if round_dollar_alert:
                alerts.append(round_dollar_alert)
                max_risk = max(max_risk, RiskLevel.MEDIUM, key=lambda x: x.value)
            
            # Velocity check
            velocity_alert = AMLService._check_velocity(transaction)
            if velocity_alert:
                alerts.append(velocity_alert)
                max_risk = max(max_risk, RiskLevel.HIGH, key=lambda x: x.value)
            
            # Cross-border check
            cross_border_alert = AMLService._check_cross_border(transaction)
            if cross_border_alert:
                alerts.append(cross_border_alert)
                max_risk = max(max_risk, cross_border_alert.risk_level, key=lambda x: x.value)
            
            # Log AML analysis
            LoggingService.log_aml_analysis(
                transaction_id=transaction.transaction_id,
                user_id=transaction.user_id,
                alerts_count=len(alerts),
                risk_level=max_risk.value,
                request_info=request_info
            )
            
            return alerts, max_risk
            
        except Exception as e:
            logger.error(f"Error in AML transaction analysis: {str(e)}")
            log_security_event(
                'aml_analysis_error',
                {'transaction_id': transaction.transaction_id, 'error': str(e)},
                transaction.user_id
            )
            return [], RiskLevel.LOW

    @staticmethod
    def assess_user_risk(user_id: int) -> RiskAssessment:
        """
        Perform comprehensive risk assessment for a user.
        
        Args:
            user_id: User ID to assess
            
        Returns:
            RiskAssessment object with detailed risk information
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")
            
            risk_factors = []
            risk_score = 0.0
            recommendations = []
            
            # Transaction volume analysis
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_transactions = Transaction.query.filter(
                and_(
                    Transaction.user_id == user_id,
                    Transaction.created_at >= thirty_days_ago,
                    Transaction.status == TransactionStatus.COMPLETED
                )
            ).all()
            
            total_volume = sum(tx.amount for tx in recent_transactions)
            transaction_count = len(recent_transactions)
            
            # High volume risk
            if total_volume > 100000:
                risk_factors.append("High transaction volume")
                risk_score += 0.3
                recommendations.append("Enhanced monitoring required")
            
            # High frequency risk
            if transaction_count > 50:
                risk_factors.append("High transaction frequency")
                risk_score += 0.2
                recommendations.append("Review transaction patterns")
            
            # Account age risk
            account_age = datetime.utcnow() - user.created_at
            if account_age < timedelta(days=30):
                risk_factors.append("New account")
                risk_score += 0.2
                recommendations.append("Enhanced due diligence")
            
            # Geographic risk
            if hasattr(user, 'country') and user.country in AMLService.HIGH_RISK_COUNTRIES:
                risk_factors.append("High-risk jurisdiction")
                risk_score += 0.4
                recommendations.append("Enhanced due diligence required")
            
            # Determine overall risk level
            if risk_score >= 0.7:
                overall_risk = RiskLevel.CRITICAL
            elif risk_score >= 0.5:
                overall_risk = RiskLevel.HIGH
            elif risk_score >= 0.3:
                overall_risk = RiskLevel.MEDIUM
            else:
                overall_risk = RiskLevel.LOW
            
            assessment = RiskAssessment(
                user_id=user_id,
                overall_risk=overall_risk,
                risk_score=risk_score,
                factors=risk_factors,
                recommendations=recommendations,
                assessed_at=datetime.utcnow()
            )
            
            # Log risk assessment
            LoggingService.log_risk_assessment(
                user_id=user_id,
                risk_level=overall_risk.value,
                risk_score=risk_score,
                factors=risk_factors
            )
            
            return assessment
            
        except Exception as e:
            logger.error(f"Error in user risk assessment: {str(e)}")
            raise

    @staticmethod
    def screen_sanctions(name: str, address: str = None) -> Tuple[bool, List[str]]:
        """
        Screen against sanctions lists.
        
        Args:
            name: Name to screen
            address: Optional address to screen
            
        Returns:
            Tuple of (is_match, match_details)
        """
        try:
            matches = []
            name_clean = sanitize_input(name).upper()
            
            # Screen against individuals
            for sanctioned_name in AMLService.SANCTIONS_LIST['individuals']:
                if sanctioned_name.upper() in name_clean or name_clean in sanctioned_name.upper():
                    matches.append(f"Individual match: {sanctioned_name}")
            
            # Screen against entities
            for sanctioned_entity in AMLService.SANCTIONS_LIST['entities']:
                if sanctioned_entity.upper() in name_clean or name_clean in sanctioned_entity.upper():
                    matches.append(f"Entity match: {sanctioned_entity}")
            
            # Screen address if provided
            if address:
                address_clean = sanitize_input(address).upper()
                for sanctioned_address in AMLService.SANCTIONS_LIST['addresses']:
                    if sanctioned_address.upper() in address_clean:
                        matches.append(f"Address match: {sanctioned_address}")
            
            is_match = len(matches) > 0
            
            if is_match:
                log_security_event(
                    'sanctions_match',
                    {'name': name, 'matches': matches},
                    None
                )
            
            return is_match, matches
            
        except Exception as e:
            logger.error(f"Error in sanctions screening: {str(e)}")
            return False, []

    @staticmethod
    def generate_sar_report(user_id: int, reason: str) -> Dict[str, Any]:
        """
        Generate Suspicious Activity Report (SAR).
        
        Args:
            user_id: User ID for the report
            reason: Reason for the SAR
            
        Returns:
            SAR report dictionary
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")
            
            # Get recent transactions
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            transactions = Transaction.query.filter(
                and_(
                    Transaction.user_id == user_id,
                    Transaction.created_at >= thirty_days_ago
                )
            ).all()
            
            # Calculate statistics
            total_volume = sum(tx.amount for tx in transactions)
            transaction_count = len(transactions)
            avg_transaction = total_volume / transaction_count if transaction_count > 0 else 0
            
            sar_report = {
                'report_id': f"SAR-{datetime.utcnow().strftime('%Y%m%d')}-{user_id}",
                'generated_at': datetime.utcnow().isoformat(),
                'user_info': {
                    'user_id': user_id,
                    'email': user.email,
                    'full_name': user.full_name,
                    'account_created': user.created_at.isoformat(),
                    'country': getattr(user, 'country', 'Unknown')
                },
                'suspicious_activity': {
                    'reason': reason,
                    'detection_date': datetime.utcnow().isoformat(),
                    'transaction_count': transaction_count,
                    'total_volume': float(total_volume),
                    'average_transaction': float(avg_transaction),
                    'currency_breakdown': AMLService._get_currency_breakdown(transactions)
                },
                'transactions': [
                    {
                        'transaction_id': tx.transaction_id,
                        'amount': float(tx.amount),
                        'currency': tx.currency,
                        'type': tx.transaction_type.value,
                        'status': tx.status.value,
                        'created_at': tx.created_at.isoformat(),
                        'description': tx.description
                    }
                    for tx in transactions
                ],
                'compliance_officer': 'System Generated',
                'status': 'PENDING_REVIEW'
            }
            
            # Log SAR generation
            LoggingService.log_sar_generation(
                user_id=user_id,
                report_id=sar_report['report_id'],
                reason=reason
            )
            
            return sar_report
            
        except Exception as e:
            logger.error(f"Error generating SAR report: {str(e)}")
            raise

    @staticmethod
    def _check_rapid_transactions(transaction: Transaction) -> List[AMLAlert]:
        """Check for rapid transaction patterns."""
        alerts = []
        
        try:
            window_start = datetime.utcnow() - AMLService.RAPID_TRANSACTION_WINDOW
            recent_count = Transaction.query.filter(
                and_(
                    Transaction.user_id == transaction.user_id,
                    Transaction.created_at >= window_start,
                    Transaction.status == TransactionStatus.COMPLETED
                )
            ).count()
            
            if recent_count >= AMLService.RAPID_TRANSACTION_COUNT:
                alert = AMLAlert(
                    alert_type=AMLAlertType.RAPID_TRANSACTIONS,
                    risk_level=RiskLevel.HIGH,
                    user_id=transaction.user_id,
                    transaction_id=transaction.transaction_id,
                    description=f"Rapid transactions: {recent_count} in {AMLService.RAPID_TRANSACTION_WINDOW}",
                    score=0.8,
                    metadata={
                        'transaction_count': recent_count,
                        'time_window': str(AMLService.RAPID_TRANSACTION_WINDOW),
                        'threshold': AMLService.RAPID_TRANSACTION_COUNT
                    },
                    created_at=datetime.utcnow()
                )
                alerts.append(alert)
                
        except Exception as e:
            logger.error(f"Error checking rapid transactions: {str(e)}")
            
        return alerts

    @staticmethod
    def _check_structuring(transaction: Transaction) -> Optional[AMLAlert]:
        """Check for potential structuring (transactions just below reporting threshold)."""
        try:
            if (AMLService.STRUCTURING_THRESHOLD <= transaction.amount < AMLService.LARGE_TRANSACTION_THRESHOLD):
                return AMLAlert(
                    alert_type=AMLAlertType.STRUCTURING,
                    risk_level=RiskLevel.HIGH,
                    user_id=transaction.user_id,
                    transaction_id=transaction.transaction_id,
                    description=f"Potential structuring: {transaction.amount} just below threshold",
                    score=0.7,
                    metadata={
                        'amount': float(transaction.amount),
                        'threshold': float(AMLService.LARGE_TRANSACTION_THRESHOLD),
                        'structuring_threshold': float(AMLService.STRUCTURING_THRESHOLD)
                    },
                    created_at=datetime.utcnow()
                )
        except Exception as e:
            logger.error(f"Error checking structuring: {str(e)}")
            
        return None

    @staticmethod
    def _check_round_dollar(transaction: Transaction) -> Optional[AMLAlert]:
        """Check for round dollar amounts which may indicate suspicious activity."""
        try:
            # Check if amount is a round number (ends in multiple zeros)
            amount_str = str(float(transaction.amount))
            if amount_str.endswith('00.0') and transaction.amount >= 1000:
                return AMLAlert(
                    alert_type=AMLAlertType.ROUND_DOLLAR,
                    risk_level=RiskLevel.MEDIUM,
                    user_id=transaction.user_id,
                    transaction_id=transaction.transaction_id,
                    description=f"Round dollar amount: {transaction.amount}",
                    score=0.4,
                    metadata={'amount': float(transaction.amount)},
                    created_at=datetime.utcnow()
                )
        except Exception as e:
            logger.error(f"Error checking round dollar: {str(e)}")
            
        return None

    @staticmethod
    def _check_velocity(transaction: Transaction) -> Optional[AMLAlert]:
        """Check daily transaction velocity."""
        try:
            today = datetime.utcnow().date()
            daily_total = db.session.query(func.sum(Transaction.amount)).filter(
                and_(
                    Transaction.user_id == transaction.user_id,
                    func.date(Transaction.created_at) == today,
                    Transaction.status == TransactionStatus.COMPLETED
                )
            ).scalar() or 0
            
            if daily_total > AMLService.VELOCITY_DAILY_LIMIT:
                return AMLAlert(
                    alert_type=AMLAlertType.VELOCITY_CHECK,
                    risk_level=RiskLevel.HIGH,
                    user_id=transaction.user_id,
                    transaction_id=transaction.transaction_id,
                    description=f"Daily velocity exceeded: {daily_total}",
                    score=0.8,
                    metadata={
                        'daily_total': float(daily_total),
                        'limit': float(AMLService.VELOCITY_DAILY_LIMIT)
                    },
                    created_at=datetime.utcnow()
                )
        except Exception as e:
            logger.error(f"Error checking velocity: {str(e)}")
            
        return None

    @staticmethod
    def _check_cross_border(transaction: Transaction) -> Optional[AMLAlert]:
        """Check for cross-border transactions to high-risk countries."""
        try:
            # Check recipient country if available
            if hasattr(transaction, 'recipient_country') and transaction.recipient_country:
                country_code = transaction.recipient_country.upper()
                if country_code in AMLService.HIGH_RISK_COUNTRIES:
                    return AMLAlert(
                        alert_type=AMLAlertType.CROSS_BORDER,
                        risk_level=RiskLevel.CRITICAL,
                        user_id=transaction.user_id,
                        transaction_id=transaction.transaction_id,
                        description=f"Transaction to high-risk country: {country_code}",
                        score=0.9,
                        metadata={'recipient_country': country_code},
                        created_at=datetime.utcnow()
                    )
        except Exception as e:
            logger.error(f"Error checking cross-border: {str(e)}")
            
        return None

    @staticmethod
    def _get_currency_breakdown(transactions: List[Transaction]) -> Dict[str, float]:
        """Get currency breakdown for transactions."""
        breakdown = {}
        for tx in transactions:
            currency = tx.currency
            if currency not in breakdown:
                breakdown[currency] = 0.0
            breakdown[currency] += float(tx.amount)
        return breakdown

    @staticmethod
    def _get_request_info() -> Dict[str, Any]:
        """Get request information for logging."""
        try:
            if request:
                return {
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'method': request.method,
                    'url': request.url,
                    'headers': dict(request.headers),
                    'timestamp': datetime.utcnow().isoformat()
                }
        except Exception:
            pass
        
        return {
            'ip_address': 'unknown',
            'user_agent': 'unknown',
            'method': 'unknown',
            'url': 'unknown',
            'headers': {},
            'timestamp': datetime.utcnow().isoformat()
        }