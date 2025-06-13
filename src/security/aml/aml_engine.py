import os
import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from models.aml import (
    AMLTransaction,
    TransactionPattern,
    TransactionPatternType,
    TransactionRiskLevel,
    AMLAlert
)
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

logger = logging.getLogger(__name__)

class AMLEngine:
    def __init__(self, config=None):
        self.config = config
        self.logger = SecurityLogger(config)
        self.threat_hunter = ThreatHunting(self.logger)
        self.patterns = self._load_patterns()
        self.rules = self._load_rules()
        
    def _load_patterns(self) -> Dict[str, Any]:
        """Load AML patterns"""
        return {
            'large_amount': {
                'threshold': 10000,
                'window': timedelta(days=1),
                'description': 'Large amount transaction'
            },
            'frequent_transactions': {
                'threshold': 5,
                'window': timedelta(hours=24),
                'description': 'Frequent transactions'
            },
            'suspicious_pattern': {
                'patterns': [
                    {'type': 'round_numbers', 'threshold': 0.9},
                    {'type': 'multiple_of', 'value': 1000, 'threshold': 0.8}
                ],
                'description': 'Suspicious transaction pattern'
            },
            'unusual_activity': {
                'threshold': 3,
                'window': timedelta(days=7),
                'description': 'Unusual activity pattern'
            },
            'geographic_risk': {
                'high_risk_countries': ['AF', 'DZ', 'BD'],
                'description': 'High-risk geographic location'
            },
            'time_pattern': {
                'suspicious_hours': [2, 3, 4],
                'description': 'Suspicious time pattern'
            }
        }
    
    def _load_rules(self) -> Dict[str, Any]:
        """Load AML rules"""
        return {
            'amount_rules': {
                'large_amount': {'threshold': 10000, 'score': 30},
                'very_large_amount': {'threshold': 50000, 'score': 50}
            },
            'pattern_rules': {
                'frequent_transactions': {'threshold': 5, 'window': 24, 'score': 25},
                'suspicious_pattern': {'threshold': 0.8, 'score': 35},
                'unusual_activity': {'threshold': 3, 'window': 7, 'score': 20},
                'geographic_risk': {'score': 25},
                'time_pattern': {'score': 15}
            },
            'combined_rules': {
                'large_amount_and_frequent': {'score': 60},
                'multiple_patterns': {'threshold': 3, 'score': 75}
            }
        }
    
    def analyze_transaction(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction for AML risks"""
        analysis = {
            'transaction': transaction,
            'risk_score': 0,
            'patterns': [],
            'alerts': [],
            'recommendations': []
        }
        
        # Analyze transaction patterns
        patterns = self._detect_patterns(transaction)
        analysis['patterns'].extend(patterns)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(transaction, patterns)
        analysis['risk_score'] = risk_score
        
        # Generate alerts if necessary
        alerts = self._generate_alerts(transaction, patterns, risk_score)
        analysis['alerts'].extend(alerts)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(transaction, patterns)
        analysis['recommendations'].extend(recommendations)
        
        return analysis
    
    def _detect_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in transaction"""
        patterns = []
        
        # Check large amount pattern
        if self._detect_large_amount(transaction):
            patterns.append({
                'type': TransactionPatternType.LARGE_AMOUNT,
                'data': {'amount': transaction['amount']},
                'score': self.patterns['large_amount']['score']
            })
            
        # Check frequent transactions
        if self._detect_frequent_transactions(transaction):
            patterns.append({
                'type': TransactionPatternType.FREQUENT_TRANSACTIONS,
                'data': {'count': self._get_transaction_count(transaction)},
                'score': self.patterns['frequent_transactions']['score']
            })
            
        # Check suspicious patterns
        if self._detect_suspicious_pattern(transaction):
            patterns.append({
                'type': TransactionPatternType.SUSPICIOUS_PATTERN,
                'data': {'pattern': self._get_suspicious_pattern(transaction)},
                'score': self.patterns['suspicious_pattern']['score']
            })
            
        # Check unusual activity
        if self._detect_unusual_activity(transaction):
            patterns.append({
                'type': TransactionPatternType.UNUSUAL_ACTIVITY,
                'data': {'activity': self._get_activity_pattern(transaction)},
                'score': self.patterns['unusual_activity']['score']
            })
            
        # Check geographic risk
        if self._detect_geographic_risk(transaction):
            patterns.append({
                'type': TransactionPatternType.GEOGRAPHIC_RISK,
                'data': {'country': transaction.get('country', 'Unknown')},
                'score': self.patterns['geographic_risk']['score']
            })
            
        # Check time pattern
        if self._detect_time_pattern(transaction):
            patterns.append({
                'type': TransactionPatternType.TIME_PATTERN,
                'data': {'hour': transaction.get('hour', 0)},
                'score': self.patterns['time_pattern']['score']
            })
            
        return patterns
    
    def _calculate_risk_score(self, transaction: Dict[str, Any], patterns: List[Dict[str, Any]]) -> float:
        """Calculate transaction risk score"""
        score = 0
        
        # Base score based on amount
        if transaction['amount'] > 10000:
            score += 30
        elif transaction['amount'] > 5000:
            score += 20
        elif transaction['amount'] > 1000:
            score += 10
            
        # Pattern-based scoring
        for pattern in patterns:
            score += pattern['score']
            
        # Combined pattern scoring
        if len(patterns) >= 2:
            score += 15
            
        return min(score, 100)
    
    def _generate_alerts(self, transaction: Dict[str, Any], 
                        patterns: List[Dict[str, Any]], 
                        risk_score: float) -> List[Dict[str, Any]]:
        """Generate AML alerts"""
        alerts = []
        
        # Generate alert based on risk score
        if risk_score >= 80:
            alerts.append({
                'type': 'high_risk',
                'severity': TransactionRiskLevel.CRITICAL,
                'description': 'High risk transaction detected',
                'recommendation': 'Immediate review required'
            })
        elif risk_score >= 60:
            alerts.append({
                'type': 'medium_risk',
                'severity': TransactionRiskLevel.HIGH,
                'description': 'Medium risk transaction detected',
                'recommendation': 'Review required'
            })
            
        # Generate pattern-specific alerts
        for pattern in patterns:
            alerts.append({
                'type': pattern['type'],
                'severity': TransactionRiskLevel.MEDIUM,
                'description': f"{pattern['type'].value} pattern detected",
                'recommendation': 'Monitor transaction'
            })
            
        return alerts
    
    def _generate_recommendations(self, transaction: Dict[str, Any], 
                                patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations"""
        recommendations = []
        
        # Base recommendations
        recommendations.append({
            'type': 'monitor',
            'description': 'Monitor transaction activity',
            'priority': 'high'
        })
        
        # Pattern-specific recommendations
        for pattern in patterns:
            recommendation = self._get_recommendation_for_pattern(pattern)
            if recommendation:
                recommendations.append(recommendation)
                
        return recommendations
    
    def _get_recommendation_for_pattern(self, pattern: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get recommendation for specific pattern"""
        recommendations = {
            TransactionPatternType.LARGE_AMOUNT: {
                'type': 'review',
                'description': 'Review large amount transaction',
                'priority': 'high'
            },
            TransactionPatternType.FREQUENT_TRANSACTIONS: {
                'type': 'monitor',
                'description': 'Monitor frequent transactions',
                'priority': 'medium'
            },
            TransactionPatternType.SUSPICIOUS_PATTERN: {
                'type': 'investigate',
                'description': 'Investigate suspicious pattern',
                'priority': 'high'
            },
            TransactionPatternType.UNUSUAL_ACTIVITY: {
                'type': 'monitor',
                'description': 'Monitor unusual activity',
                'priority': 'medium'
            },
            TransactionPatternType.GEOGRAPHIC_RISK: {
                'type': 'review',
                'description': 'Review geographic risk',
                'priority': 'high'
            },
            TransactionPatternType.TIME_PATTERN: {
                'type': 'monitor',
                'description': 'Monitor time-based pattern',
                'priority': 'low'
            }
        }
        
        return recommendations.get(pattern['type'])
    
    def _detect_large_amount(self, transaction: Dict[str, Any]) -> bool:
        """Detect large amount transactions"""
        return transaction['amount'] > self.patterns['large_amount']['threshold']
    
    def _detect_frequent_transactions(self, transaction: Dict[str, Any]) -> bool:
        """Detect frequent transactions"""
        count = self._get_transaction_count(transaction)
        return count >= self.patterns['frequent_transactions']['threshold']
    
    def _detect_suspicious_pattern(self, transaction: Dict[str, Any]) -> bool:
        """Detect suspicious patterns"""
        patterns = self.patterns['suspicious_pattern']['patterns']
        return any(self._match_pattern(transaction, p) for p in patterns)
    
    def _detect_unusual_activity(self, transaction: Dict[str, Any]) -> bool:
        """Detect unusual activity"""
        return self._get_activity_score(transaction) >= self.patterns['unusual_activity']['threshold']
    
    def _detect_geographic_risk(self, transaction: Dict[str, Any]) -> bool:
        """Detect geographic risk"""
        country = transaction.get('country', 'Unknown')
        return country in self.patterns['geographic_risk']['high_risk_countries']
    
    def _detect_time_pattern(self, transaction: Dict[str, Any]) -> bool:
        """Detect time-based patterns"""
        hour = transaction.get('hour', 0)
        return hour in self.patterns['time_pattern']['suspicious_hours']
    
    def _get_transaction_count(self, transaction: Dict[str, Any]) -> int:
        """Get transaction count in time window"""
        # Implementation of transaction counting
        return 0
    
    def _get_suspicious_pattern(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Get suspicious pattern details"""
        # Implementation of pattern detection
        return {}
    
    def _get_activity_pattern(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Get activity pattern details"""
        # Implementation of activity analysis
        return {}
    
    def _get_activity_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate activity score"""
        # Implementation of activity scoring
        return 0.0
    
    def _match_pattern(self, transaction: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """Match transaction against pattern"""
        # Implementation of pattern matching
        return False
