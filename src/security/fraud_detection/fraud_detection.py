import numpy as np
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from models.aml import (
    AMLTransaction,
    TransactionPattern,
    TransactionRiskLevel,
    AMLAlert
)
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

logger = logging.getLogger(__name__)

class FraudDetection:
    def __init__(self, config=None):
        self.config = config
        self.logger = SecurityLogger(config)
        self.threat_hunter = ThreatHunting(self.logger)
        self.models = {
            'amount': self._create_model(),
            'pattern': self._create_model(),
            'behavior': self._create_model()
        }
        self.scalers = {
            'amount': StandardScaler(),
            'pattern': StandardScaler(),
            'behavior': StandardScaler()
        }
        self.patterns = self._load_patterns()
        
    def _create_model(self) -> IsolationForest:
        """Create fraud detection model"""
        return IsolationForest(
            n_estimators=100,
            contamination=0.01,
            max_samples='auto',
            random_state=42
        )
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load fraud patterns"""
        return {
            'amount_patterns': {
                'thresholds': [1000, 5000, 10000],
                'weights': [0.1, 0.3, 0.5]
            },
            'time_patterns': {
                'suspicious_hours': [2, 3, 4],
                'weights': [0.2, 0.4, 0.6]
            },
            'behavior_patterns': {
                'frequent_transactions': {'threshold': 5, 'window': 24},
                'unusual_locations': {'threshold': 0.8},
                'device_changes': {'threshold': 0.5}
            }
        }
    
    def train_models(self, transactions: List[Dict[str, Any]]) -> None:
        """Train fraud detection models"""
        # Prepare features
        amount_features = self._extract_amount_features(transactions)
        pattern_features = self._extract_pattern_features(transactions)
        behavior_features = self._extract_behavior_features(transactions)
        
        # Scale features
        amount_features = self.scalers['amount'].fit_transform(amount_features)
        pattern_features = self.scalers['pattern'].fit_transform(pattern_features)
        behavior_features = self.scalers['behavior'].fit_transform(behavior_features)
        
        # Train models
        self.models['amount'].fit(amount_features)
        self.models['pattern'].fit(pattern_features)
        self.models['behavior'].fit(behavior_features)
    
    def detect_fraud(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential fraud in transaction"""
        detection = {
            'transaction': transaction,
            'scores': {},
            'alerts': [],
            'recommendations': []
        }
        
        # Extract features
        amount_features = self._extract_amount_features([transaction])
        pattern_features = self._extract_pattern_features([transaction])
        behavior_features = self._extract_behavior_features([transaction])
        
        # Scale features
        amount_features = self.scalers['amount'].transform(amount_features)
        pattern_features = self.scalers['pattern'].transform(pattern_features)
        behavior_features = self.scalers['behavior'].transform(behavior_features)
        
        # Detect fraud
        fraud_scores = self._calculate_fraud_scores(
            amount_features,
            pattern_features,
            behavior_features
        )
        
        detection['scores'] = fraud_scores
        
        # Generate alerts if necessary
        if any(score >= 0.8 for score in fraud_scores.values()):
            alerts = self._generate_alerts(transaction, fraud_scores)
            detection['alerts'].extend(alerts)
            
        # Generate recommendations
        recommendations = self._generate_recommendations(transaction, fraud_scores)
        detection['recommendations'].extend(recommendations)
        
        return detection
    
    def _calculate_fraud_scores(self, 
                              amount_features: np.ndarray,
                              pattern_features: np.ndarray,
                              behavior_features: np.ndarray) -> Dict[str, float]:
        """Calculate fraud scores"""
        scores = {}
        
        # Amount-based score
        amount_score = -self.models['amount'].decision_function(amount_features)[0]
        scores['amount'] = float(amount_score)
        
        # Pattern-based score
        pattern_score = -self.models['pattern'].decision_function(pattern_features)[0]
        scores['pattern'] = float(pattern_score)
        
        # Behavior-based score
        behavior_score = -self.models['behavior'].decision_function(behavior_features)[0]
        scores['behavior'] = float(behavior_score)
        
        return scores
    
    def _generate_alerts(self, transaction: Dict[str, Any], 
                        scores: Dict[str, float]) -> List[Dict[str, Any]]:
        """Generate fraud alerts"""
        alerts = []
        
        # Generate alerts based on scores
        if scores['amount'] >= 0.8:
            alerts.append({
                'type': 'amount_fraud',
                'severity': TransactionRiskLevel.CRITICAL,
                'description': 'High risk amount transaction',
                'recommendation': 'Immediate review required'
            })
            
        if scores['pattern'] >= 0.8:
            alerts.append({
                'type': 'pattern_fraud',
                'severity': TransactionRiskLevel.HIGH,
                'description': 'Suspicious transaction pattern',
                'recommendation': 'Review transaction'
            })
            
        if scores['behavior'] >= 0.8:
            alerts.append({
                'type': 'behavior_fraud',
                'severity': TransactionRiskLevel.HIGH,
                'description': 'Unusual behavior detected',
                'recommendation': 'Monitor activity'
            })
            
        return alerts
    
    def _generate_recommendations(self, transaction: Dict[str, Any], 
                                scores: Dict[str, float]) -> List[Dict[str, Any]]:
        """Generate fraud recommendations"""
        recommendations = []
        
        # Base recommendations
        recommendations.append({
            'type': 'monitor',
            'description': 'Monitor transaction activity',
            'priority': 'high'
        })
        
        # Score-based recommendations
        if any(score >= 0.8 for score in scores.values()):
            recommendations.append({
                'type': 'review',
                'description': 'Review transaction',
                'priority': 'high'
            })
            
        if any(score >= 0.6 for score in scores.values()):
            recommendations.append({
                'type': 'monitor',
                'description': 'Monitor transaction',
                'priority': 'medium'
            })
            
        return recommendations
    
    def _extract_amount_features(self, transactions: List[Dict[str, Any]]) -> np.ndarray:
        """Extract amount-based features"""
        features = []
        
        for transaction in transactions:
            features.append([
                transaction['amount'],
                transaction.get('currency', 'USD'),
                transaction.get('source_country', 'Unknown'),
                transaction.get('destination_country', 'Unknown'),
                transaction.get('hour', 0),
                transaction.get('day_of_week', 0)
            ])
            
        return np.array(features)
    
    def _extract_pattern_features(self, transactions: List[Dict[str, Any]]) -> np.ndarray:
        """Extract pattern-based features"""
        features = []
        
        for transaction in transactions:
            features.append([
                transaction.get('transaction_type', 'Unknown'),
                transaction.get('source_account_type', 'Unknown'),
                transaction.get('destination_account_type', 'Unknown'),
                transaction.get('device_type', 'Unknown'),
                transaction.get('ip_address', 'Unknown')
            ])
            
        return np.array(features)
    
    def _extract_behavior_features(self, transactions: List[Dict[str, Any]]) -> np.ndarray:
        """Extract behavior-based features"""
        features = []
        
        for transaction in transactions:
            features.append([
                self._get_transaction_frequency(transaction),
                self._get_location_distance(transaction),
                self._get_device_change_score(transaction),
                self._get_time_pattern_score(transaction),
                self._get_behavior_score(transaction)
            ])
            
        return np.array(features)
    
    def _get_transaction_frequency(self, transaction: Dict[str, Any]) -> float:
        """Calculate transaction frequency score"""
        # Implementation of frequency calculation
        return 0.0
    
    def _get_location_distance(self, transaction: Dict[str, Any]) -> float:
        """Calculate location distance score"""
        # Implementation of distance calculation
        return 0.0
    
    def _get_device_change_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate device change score"""
        # Implementation of device change scoring
        return 0.0
    
    def _get_time_pattern_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate time pattern score"""
        # Implementation of time pattern scoring
        return 0.0
    
    def _get_behavior_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate overall behavior score"""
        # Implementation of behavior scoring
        return 0.0
