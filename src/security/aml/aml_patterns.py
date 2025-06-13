from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from models.aml import (
    TransactionPatternType,
    TransactionRiskLevel
)

class AMLPatterns:
    def __init__(self):
        self.patterns = {
            'amount': self._load_amount_patterns(),
            'time': self._load_time_patterns(),
            'behavior': self._load_behavior_patterns(),
            'geographic': self._load_geographic_patterns(),
            'device': self._load_device_patterns()
        }
        
    def _load_amount_patterns(self) -> Dict[str, Any]:
        """Load amount-based patterns"""
        return {
            'large_amount': {
                'thresholds': [1000, 5000, 10000, 50000],
                'weights': [0.1, 0.3, 0.5, 0.7],
                'description': 'Large amount transaction'
            },
            'round_numbers': {
                'threshold': 0.9,
                'description': 'Round number transaction'
            },
            'multiple_of': {
                'values': [1000, 5000, 10000],
                'threshold': 0.8,
                'description': 'Multiple of specific amounts'
            }
        }
    
    def _load_time_patterns(self) -> Dict[str, Any]:
        """Load time-based patterns"""
        return {
            'suspicious_hours': {
                'hours': [2, 3, 4],
                'description': 'Transactions during suspicious hours'
            },
            'frequent_transactions': {
                'threshold': 5,
                'window': timedelta(hours=24),
                'description': 'Frequent transactions'
            },
            'time_sequence': {
                'threshold': 0.8,
                'description': 'Unusual time sequence'
            }
        }
    
    def _load_behavior_patterns(self) -> Dict[str, Any]:
        """Load behavior-based patterns"""
        return {
            'account_switching': {
                'threshold': 3,
                'window': timedelta(days=7),
                'description': 'Frequent account switching'
            },
            'multiple_devices': {
                'threshold': 3,
                'window': timedelta(days=30),
                'description': 'Multiple devices used'
            },
            'location_changes': {
                'threshold': 500,  # kilometers
                'window': timedelta(hours=24),
                'description': 'Unusual location changes'
            }
        }
    
    def _load_geographic_patterns(self) -> Dict[str, Any]:
        """Load geographic patterns"""
        return {
            'high_risk_countries': {
                'countries': ['AF', 'DZ', 'BD'],
                'description': 'Transactions to/from high-risk countries'
            },
            'cross_border': {
                'threshold': 0.8,
                'description': 'Frequent cross-border transactions'
            },
            'multiple_countries': {
                'threshold': 3,
                'window': timedelta(days=30),
                'description': 'Transactions in multiple countries'
            }
        }
    
    def _load_device_patterns(self) -> Dict[str, Any]:
        """Load device-based patterns"""
        return {
            'device_switching': {
                'threshold': 3,
                'window': timedelta(days=7),
                'description': 'Frequent device switching'
            },
            'multiple_ip': {
                'threshold': 3,
                'window': timedelta(days=30),
                'description': 'Multiple IP addresses used'
            },
            'unusual_device': {
                'threshold': 0.8,
                'description': 'Unusual device characteristics'
            }
        }
    
    def detect_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect all patterns in a transaction"""
        patterns = []
        
        # Amount patterns
        amount_patterns = self._detect_amount_patterns(transaction)
        patterns.extend(amount_patterns)
        
        # Time patterns
        time_patterns = self._detect_time_patterns(transaction)
        patterns.extend(time_patterns)
        
        # Behavior patterns
        behavior_patterns = self._detect_behavior_patterns(transaction)
        patterns.extend(behavior_patterns)
        
        # Geographic patterns
        geo_patterns = self._detect_geographic_patterns(transaction)
        patterns.extend(geo_patterns)
        
        # Device patterns
        device_patterns = self._detect_device_patterns(transaction)
        patterns.extend(device_patterns)
        
        return patterns
    
    def _detect_amount_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect amount-based patterns"""
        patterns = []
        amount = transaction['amount']
        
        # Large amount pattern
        for i, threshold in enumerate(self.patterns['amount']['large_amount']['thresholds']):
            if amount > threshold:
                patterns.append({
                    'type': TransactionPatternType.LARGE_AMOUNT,
                    'data': {'amount': amount, 'threshold': threshold},
                    'score': self.patterns['amount']['large_amount']['weights'][i],
                    'description': self.patterns['amount']['large_amount']['description']
                })
        
        # Round numbers pattern
        if self._is_round_number(amount):
            patterns.append({
                'type': TransactionPatternType.SUSPICIOUS_PATTERN,
                'data': {'amount': amount},
                'score': self.patterns['amount']['round_numbers']['threshold'],
                'description': self.patterns['amount']['round_numbers']['description']
            })
        
        return patterns
    
    def _detect_time_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect time-based patterns"""
        patterns = []
        hour = transaction.get('hour', 0)
        
        # Suspicious hours pattern
        if hour in self.patterns['time']['suspicious_hours']['hours']:
            patterns.append({
                'type': TransactionPatternType.TIME_PATTERN,
                'data': {'hour': hour},
                'score': 0.5,
                'description': self.patterns['time']['suspicious_hours']['description']
            })
        
        return patterns
    
    def _detect_behavior_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect behavior-based patterns"""
        patterns = []
        
        # Account switching pattern
        if self._detect_account_switching(transaction):
            patterns.append({
                'type': TransactionPatternType.UNUSUAL_ACTIVITY,
                'data': {'account_changes': self._get_account_changes(transaction)},
                'score': 0.6,
                'description': self.patterns['behavior']['account_switching']['description']
            })
        
        return patterns
    
    def _detect_geographic_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect geographic patterns"""
        patterns = []
        country = transaction.get('country', 'Unknown')
        
        # High-risk country pattern
        if country in self.patterns['geographic']['high_risk_countries']['countries']:
            patterns.append({
                'type': TransactionPatternType.GEOGRAPHIC_RISK,
                'data': {'country': country},
                'score': 0.7,
                'description': self.patterns['geographic']['high_risk_countries']['description']
            })
        
        return patterns
    
    def _detect_device_patterns(self, transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect device-based patterns"""
        patterns = []
        
        # Device switching pattern
        if self._detect_device_switching(transaction):
            patterns.append({
                'type': TransactionPatternType.UNUSUAL_ACTIVITY,
                'data': {'device_changes': self._get_device_changes(transaction)},
                'score': 0.6,
                'description': self.patterns['device']['device_switching']['description']
            })
        
        return patterns
    
    def _is_round_number(self, amount: float) -> bool:
        """Check if amount is a round number"""
        return abs(amount - round(amount)) < 0.01
    
    def _detect_account_switching(self, transaction: Dict[str, Any]) -> bool:
        """Detect account switching pattern"""
        # Implementation of account switching detection
        return False
    
    def _get_account_changes(self, transaction: Dict[str, Any]) -> int:
        """Get number of account changes"""
        # Implementation of account change counting
        return 0
    
    def _detect_device_switching(self, transaction: Dict[str, Any]) -> bool:
        """Detect device switching pattern"""
        # Implementation of device switching detection
        return False
    
    def _get_device_changes(self, transaction: Dict[str, Any]) -> int:
        """Get number of device changes"""
        # Implementation of device change counting
        return 0
