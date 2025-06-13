from typing import Dict, List, Any, Optional
import numpy as np
from datetime import datetime, timedelta
from models.aml import (
    TransactionRiskLevel,
    AMLAlert
)
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

class RiskAssessment:
    def __init__(self, config=None):
        self.config = config
        self.logger = SecurityLogger(config)
        self.threat_hunter = ThreatHunting(self.logger)
        self.risk_factors = {
            'amount': self._load_amount_risk_factors(),
            'pattern': self._load_pattern_risk_factors(),
            'behavior': self._load_behavior_risk_factors(),
            'geographic': self._load_geographic_risk_factors(),
            'device': self._load_device_risk_factors()
        }
        
    def _load_amount_risk_factors(self) -> Dict[str, Any]:
        """Load amount-based risk factors"""
        return {
            'large_amount': {
                'thresholds': [10000, 50000, 100000],
                'weights': [0.3, 0.6, 0.9],
                'description': 'Large transaction amount'
            },
            'round_numbers': {
                'threshold': 0.9,
                'weight': 0.5,
                'description': 'Round number transaction'
            },
            'multiple_of': {
                'values': [1000, 5000, 10000],
                'weights': [0.3, 0.5, 0.7],
                'description': 'Multiple of specific amounts'
            }
        }
    
    def _load_pattern_risk_factors(self) -> Dict[str, Any]:
        """Load pattern-based risk factors"""
        return {
            'frequent_transactions': {
                'threshold': 5,
                'window': timedelta(hours=24),
                'weight': 0.6,
                'description': 'Frequent transactions'
            },
            'suspicious_pattern': {
                'threshold': 0.8,
                'weight': 0.7,
                'description': 'Suspicious transaction pattern'
            },
            'time_pattern': {
                'suspicious_hours': [2, 3, 4],
                'weight': 0.5,
                'description': 'Transactions during suspicious hours'
            }
        }
    
    def _load_behavior_risk_factors(self) -> Dict[str, Any]:
        """Load behavior-based risk factors"""
        return {
            'account_switching': {
                'threshold': 3,
                'window': timedelta(days=7),
                'weight': 0.6,
                'description': 'Frequent account switching'
            },
            'multiple_devices': {
                'threshold': 3,
                'window': timedelta(days=30),
                'weight': 0.5,
                'description': 'Multiple devices used'
            },
            'location_changes': {
                'threshold': 500,  # kilometers
                'window': timedelta(hours=24),
                'weight': 0.7,
                'description': 'Unusual location changes'
            }
        }
    
    def _load_geographic_risk_factors(self) -> Dict[str, Any]:
        """Load geographic risk factors"""
        return {
            'high_risk_countries': {
                'countries': ['AF', 'DZ', 'BD'],
                'weight': 0.8,
                'description': 'Transactions to/from high-risk countries'
            },
            'cross_border': {
                'threshold': 0.8,
                'weight': 0.6,
                'description': 'Frequent cross-border transactions'
            },
            'multiple_countries': {
                'threshold': 3,
                'window': timedelta(days=30),
                'weight': 0.7,
                'description': 'Transactions in multiple countries'
            }
        }
    
    def _load_device_risk_factors(self) -> Dict[str, Any]:
        """Load device-based risk factors"""
        return {
            'device_switching': {
                'threshold': 3,
                'window': timedelta(days=7),
                'weight': 0.6,
                'description': 'Frequent device switching'
            },
            'multiple_ip': {
                'threshold': 3,
                'window': timedelta(days=30),
                'weight': 0.5,
                'description': 'Multiple IP addresses used'
            },
            'unusual_device': {
                'threshold': 0.8,
                'weight': 0.7,
                'description': 'Unusual device characteristics'
            }
        }
    
    def assess_risk(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Assess transaction risk"""
        assessment = {
            'transaction': transaction,
            'risk_score': 0,
            'risk_factors': [],
            'recommendations': [],
            'details': {}
        }
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(transaction)
        assessment['risk_score'] = risk_score
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(transaction)
        assessment['risk_factors'].extend(risk_factors)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(transaction, risk_score)
        assessment['recommendations'].extend(recommendations)
        
        # Add detailed analysis
        assessment['details'] = self._generate_detailed_analysis(transaction)
        
        return assessment
    
    def _calculate_risk_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate transaction risk score"""
        score = 0
        
        # Amount-based risk
        amount_score = self._calculate_amount_risk(transaction)
        score += amount_score
        
        # Pattern-based risk
        pattern_score = self._calculate_pattern_risk(transaction)
        score += pattern_score
        
        # Behavior-based risk
        behavior_score = self._calculate_behavior_risk(transaction)
        score += behavior_score
        
        # Geographic risk
        geo_score = self._calculate_geographic_risk(transaction)
        score += geo_score
        
        # Device risk
        device_score = self._calculate_device_risk(transaction)
        score += device_score
        
        return min(score, 1.0)
    
    def _identify_risk_factors(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify risk factors in transaction"""
        risk_factors = []
        
        # Amount-based risk factors
        if transaction['amount'] > 10000:
            risk_factors.append({
                'type': 'amount',
                'description': 'Large transaction amount',
                'score': 0.8
            })
            
        # Pattern-based risk factors
        if self._detect_suspicious_pattern(transaction):
            risk_factors.append({
                'type': 'pattern',
                'description': 'Suspicious transaction pattern',
                'score': 0.7
            })
            
        # Behavior-based risk factors
        if self._detect_unusual_behavior(transaction):
            risk_factors.append({
                'type': 'behavior',
                'description': 'Unusual transaction behavior',
                'score': 0.6
            })
            
        return risk_factors
    
    def _generate_recommendations(self, transaction: Dict[str, Any], 
                                risk_score: float) -> List[Dict[str, Any]]:
        """Generate risk-based recommendations"""
        recommendations = []
        
        # Base recommendations
        recommendations.append({
            'type': 'monitor',
            'description': 'Monitor transaction activity',
            'priority': 'high'
        })
        
        # Score-based recommendations
        if risk_score >= 0.8:
            recommendations.append({
                'type': 'immediate_review',
                'description': 'Immediate review required',
                'priority': 'critical'
            })
            
        if risk_score >= 0.6:
            recommendations.append({
                'type': 'fraud_investigation',
                'description': 'Initiate fraud investigation',
                'priority': 'high'
            })
            
        return recommendations
    
    def _generate_detailed_analysis(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed risk analysis"""
        return {
            'amount_analysis': self._analyze_amount(transaction),
            'pattern_analysis': self._analyze_pattern(transaction),
            'behavior_analysis': self._analyze_behavior(transaction),
            'geographic_analysis': self._analyze_geographic(transaction),
            'device_analysis': self._analyze_device(transaction)
        }
    
    def _analyze_amount(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction amount"""
        return {
            'amount': transaction['amount'],
            'currency': transaction.get('currency', 'USD'),
            'risk_level': self._calculate_amount_risk(transaction),
            'pattern': self._detect_amount_pattern(transaction)
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
    
    def _analyze_geographic(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic factors"""
        return {
            'country': transaction.get('country', 'Unknown'),
            'distance': self._calculate_location_distance(transaction),
            'cross_border': self._detect_cross_border(transaction)
        }
    
    def _analyze_device(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze device factors"""
        return {
            'device_type': transaction.get('device_type', 'Unknown'),
            'ip_address': transaction.get('ip_address', 'Unknown'),
            'device_score': self._calculate_device_score(transaction)
        }
    
    def _calculate_amount_risk(self, transaction: Dict[str, Any]) -> float:
        """Calculate amount-based risk"""
        if transaction['amount'] > 50000:
            return 0.9
        elif transaction['amount'] > 10000:
            return 0.7
        elif transaction['amount'] > 5000:
            return 0.5
        else:
            return 0.3
    
    def _calculate_pattern_risk(self, transaction: Dict[str, Any]) -> float:
        """Calculate pattern-based risk"""
        # Implementation of pattern risk calculation
        return 0.0
    
    def _calculate_behavior_risk(self, transaction: Dict[str, Any]) -> float:
        """Calculate behavior-based risk"""
        # Implementation of behavior risk calculation
        return 0.0
    
    def _calculate_geographic_risk(self, transaction: Dict[str, Any]) -> float:
        """Calculate geographic risk"""
        # Implementation of geographic risk calculation
        return 0.0
    
    def _calculate_device_risk(self, transaction: Dict[str, Any]) -> float:
        """Calculate device-based risk"""
        # Implementation of device risk calculation
        return 0.0
    
    def _detect_suspicious_pattern(self, transaction: Dict[str, Any]) -> bool:
        """Detect suspicious patterns"""
        # Implementation of pattern detection
        return False
    
    def _detect_unusual_behavior(self, transaction: Dict[str, Any]) -> bool:
        """Detect unusual behavior"""
        # Implementation of behavior detection
        return False
    
    def _detect_cross_border(self, transaction: Dict[str, Any]) -> bool:
        """Detect cross-border transactions"""
        # Implementation of cross-border detection
        return False
    
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
    
    def _calculate_device_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate device score"""
        # Implementation of device scoring
        return 0.0
