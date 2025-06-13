from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectKBest, f_classif
from datetime import datetime, timedelta
from models.aml import (
    TransactionRiskLevel,
    AMLAlert
)
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

class AdvancedFraudDetection:
    def __init__(self, config=None):
        self.config = config
        self.logger = SecurityLogger(config)
        self.threat_hunter = ThreatHunting(self.logger)
        self.models = {
            'amount': self._create_model(),
            'pattern': self._create_model(),
            'behavior': self._create_model()
        }
        self.feature_extractors = {
            'amount': self._extract_amount_features,
            'pattern': self._extract_pattern_features,
            'behavior': self._extract_behavior_features
        }
        
    def _create_model(self) -> Pipeline:
        """Create fraud detection model pipeline"""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('feature_selection', SelectKBest(f_classif, k=10)),
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            ))
        ])
    
    def train_models(self, transactions: List[Dict[str, Any]], labels: List[int]) -> None:
        """Train fraud detection models"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            transactions,
            labels,
            test_size=0.2,
            random_state=42
        )
        
        # Train models
        for model_type, model in self.models.items():
            # Extract features
            X_train_features = self.feature_extractors[model_type](X_train)
            X_test_features = self.feature_extractors[model_type](X_test)
            
            # Train model
            model.fit(X_train_features, y_train)
            
            # Evaluate model
            y_pred = model.predict(X_test_features)
            report = classification_report(y_test, y_pred)
            self.logger.log_event(
                SecurityEventType.AUDIT,
                SecurityEventSeverity.INFO,
                event_type='model_training',
                model_type=model_type,
                evaluation_report=report
            )
    
    def detect_fraud(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential fraud in transaction"""
        detection = {
            'transaction': transaction,
            'scores': {},
            'alerts': [],
            'recommendations': [],
            'details': {}
        }
        
        # Extract features
        amount_features = self._extract_amount_features([transaction])
        pattern_features = self._extract_pattern_features([transaction])
        behavior_features = self._extract_behavior_features([transaction])
        
        # Predict fraud
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
        
        # Add detailed analysis
        detection['details'] = self._generate_detailed_analysis(transaction)
        
        return detection
    
    def _calculate_fraud_scores(self, 
                              amount_features: np.ndarray,
                              pattern_features: np.ndarray,
                              behavior_features: np.ndarray) -> Dict[str, float]:
        """Calculate fraud scores using machine learning models"""
        scores = {}
        
        # Amount-based score
        amount_score = self.models['amount'].predict_proba(amount_features)[0][1]
        scores['amount'] = float(amount_score)
        
        # Pattern-based score
        pattern_score = self.models['pattern'].predict_proba(pattern_features)[0][1]
        scores['pattern'] = float(pattern_score)
        
        # Behavior-based score
        behavior_score = self.models['behavior'].predict_proba(behavior_features)[0][1]
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
            
        return recommendations
    
    def _generate_detailed_analysis(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed fraud analysis"""
        return {
            'amount_analysis': self._analyze_amount(transaction),
            'pattern_analysis': self._analyze_pattern(transaction),
            'behavior_analysis': self._analyze_behavior(transaction),
            'risk_factors': self._identify_risk_factors(transaction)
        }
    
    def _analyze_amount(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction amount"""
        return {
            'amount': transaction['amount'],
            'currency': transaction.get('currency', 'USD'),
            'risk_level': self._calculate_amount_risk(transaction['amount']),
            'pattern': self._detect_amount_pattern(transaction['amount'])
        }
    
    def _analyze_pattern(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction pattern"""
        return {
            'type': transaction.get('transaction_type', 'Unknown'),
            'frequency': self._calculate_frequency(transaction),
            'pattern_score': self._calculate_pattern_score(transaction)
        }
    
    def _analyze_behavior(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction behavior"""
        return {
            'device_changes': self._count_device_changes(transaction),
            'location_changes': self._calculate_location_distance(transaction),
            'behavior_score': self._calculate_behavior_score(transaction)
        }
    
    def _identify_risk_factors(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify risk factors in transaction"""
        risk_factors = []
        
        # Amount-based risk
        if transaction['amount'] > 10000:
            risk_factors.append({
                'type': 'amount',
                'description': 'Large transaction amount',
                'score': 0.8
            })
            
        # Pattern-based risk
        if self._detect_suspicious_pattern(transaction):
            risk_factors.append({
                'type': 'pattern',
                'description': 'Suspicious transaction pattern',
                'score': 0.7
            })
            
        # Behavior-based risk
        if self._detect_unusual_behavior(transaction):
            risk_factors.append({
                'type': 'behavior',
                'description': 'Unusual transaction behavior',
                'score': 0.6
            })
            
        return risk_factors
    
    def _extract_amount_features(self, transactions: List[Dict[str, Any]]) -> np.ndarray:
        """Extract amount-based features"""
        features = []
        
        for transaction in transactions:
            features.append([
                transaction['amount'],
                self._is_round_number(transaction['amount']),
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
    
    def _is_round_number(self, amount: float) -> int:
        """Check if amount is a round number"""
        return abs(amount - round(amount)) < 0.01
    
    def _calculate_amount_risk(self, amount: float) -> float:
        """Calculate amount-based risk"""
        if amount > 50000:
            return 0.9
        elif amount > 10000:
            return 0.7
        elif amount > 5000:
            return 0.5
        else:
            return 0.3
    
    def _detect_amount_pattern(self, amount: float) -> Dict[str, Any]:
        """Detect amount patterns"""
        return {
            'round_number': self._is_round_number(amount),
            'multiple_of_1000': abs(amount % 1000) < 0.01,
            'multiple_of_5000': abs(amount % 5000) < 0.01
        }
    
    def _calculate_frequency(self, transaction: Dict[str, Any]) -> float:
        """Calculate transaction frequency"""
        # Implementation of frequency calculation
        return 0.0
    
    def _calculate_pattern_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate pattern score"""
        # Implementation of pattern scoring
        return 0.0
    
    def _count_device_changes(self, transaction: Dict[str, Any]) -> int:
        """Count device changes"""
        # Implementation of device change counting
        return 0
    
    def _calculate_location_distance(self, transaction: Dict[str, Any]) -> float:
        """Calculate location distance"""
        # Implementation of distance calculation
        return 0.0
    
    def _calculate_behavior_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate behavior score"""
        # Implementation of behavior scoring
        return 0.0
    
    def _detect_suspicious_pattern(self, transaction: Dict[str, Any]) -> bool:
        """Detect suspicious patterns"""
        # Implementation of pattern detection
        return False
    
    def _detect_unusual_behavior(self, transaction: Dict[str, Any]) -> bool:
        """Detect unusual behavior"""
        # Implementation of behavior detection
        return False
