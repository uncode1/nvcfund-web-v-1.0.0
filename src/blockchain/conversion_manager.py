from typing import Dict, Any, Optional, Type, List
import logging
from datetime import datetime
from .conversion_system import BlockchainConversionSystem
from integrations.swift_integration import SWIFTIntegration
from security.logging import SecurityLogger
from security.threat_hunting import ThreatHunting

logger = logging.getLogger(__name__)

class ConversionManager:
    def __init__(self, config: Dict[str, Any], security: WebSecurity):
        self.config = config
        self.security = security
        self.logger = SecurityLogger()
        self.threat_hunter = ThreatHunting(self.logger)
        self.conversion_system = BlockchainConversionSystem(config, security)
        self.swift = SWIFTIntegration(config, security)
        
    def convert_to_fiat(self, 
                       amount: float, 
                       blockchain_currency: str, 
                       fiat_currency: str) -> Dict[str, Any]:
        """Convert blockchain currency to fiat currency"""
        try:
            # Validate conversion
            self._validate_conversion(blockchain_currency, fiat_currency)
            
            # Perform conversion
            conversion = self.conversion_system.convert_to_fiat(
                amount,
                blockchain_currency,
                fiat_currency
            )
            
            # Log conversion
            self.logger.log_event(
                SecurityEventType.AUDIT,
                SecurityEventSeverity.INFO,
                event_type='blockchain_to_fiat',
                details=conversion
            )
            
            return conversion
            
        except Exception as e:
            logger.error(f"Blockchain to fiat conversion failed: {e}")
            raise
    
    def convert_to_blockchain(self, 
                            amount: float, 
                            fiat_currency: str, 
                            blockchain_currency: str) -> Dict[str, Any]:
        """Convert fiat currency to blockchain currency"""
        try:
            # Validate conversion
            self._validate_conversion(blockchain_currency, fiat_currency)
            
            # Perform conversion
            conversion = self.conversion_system.convert_to_blockchain(
                amount,
                fiat_currency,
                blockchain_currency
            )
            
            # Log conversion
            self.logger.log_event(
                SecurityEventType.AUDIT,
                SecurityEventSeverity.INFO,
                event_type='fiat_to_blockchain',
                details=conversion
            )
            
            return conversion
            
        except Exception as e:
            logger.error(f"Fiat to blockchain conversion failed: {e}")
            raise
    
    def _validate_conversion(self, 
                            blockchain_currency: str, 
                            fiat_currency: str) -> None:
        """Validate conversion parameters"""
        # Validate blockchain currency
        if blockchain_currency not in self.config.get('BLOCKCHAIN_CURRENCIES', []):
            raise ValueError(f"Unsupported blockchain currency: {blockchain_currency}")
            
        # Validate fiat currency
        if fiat_currency not in self.config.get('ALLOWED_CURRENCIES', []):
            raise ValueError(f"Unsupported fiat currency: {fiat_currency}")
            
        # Validate amount
        if amount <= 0:
            raise ValueError("Amount must be greater than zero")
            
        # Check conversion limits
        self._check_conversion_limits(blockchain_currency, fiat_currency, amount)
    
    def _check_conversion_limits(self, 
                                blockchain_currency: str, 
                                fiat_currency: str, 
                                amount: float) -> None:
        """Check conversion limits"""
        # Get limits from config
        limits = self.config.get('CONVERSION_LIMITS', {})
        
        # Check blockchain currency limits
        if blockchain_currency in limits:
            max_amount = limits[blockchain_currency].get('max_amount')
            if max_amount and amount > max_amount:
                raise ValueError(f"Amount exceeds maximum limit for {blockchain_currency}")
                
        # Check fiat currency limits
        if fiat_currency in limits:
            max_amount = limits[fiat_currency].get('max_amount')
            if max_amount and amount > max_amount:
                raise ValueError(f"Amount exceeds maximum limit for {fiat_currency}")
    
    def monitor_conversions(self) -> Dict[str, Any]:
        """Monitor conversion activity"""
        try:
            # Get blockchain conversions
            blockchain_conversions = self.conversion_system.monitor_conversions()
            
            # Get SWIFT activity
            swift_activity = self.swift.monitor_activity()
            
            return {
                'blockchain_conversions': blockchain_conversions,
                'swift_activity': swift_activity,
                'anomalies': self._detect_conversion_anomalies(
                    blockchain_conversions,
                    swift_activity
                )
            }
            
        except Exception as e:
            logger.error(f"Error monitoring conversions: {e}")
            raise
    
    def _detect_conversion_anomalies(self, 
                                    blockchain_conversions: Dict[str, Any],
                                    swift_activity: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect conversion anomalies"""
        anomalies = []
        
        # Check for unusual patterns
        if self._is_volume_anomalous(blockchain_conversions):
            anomalies.append({
                'type': 'volume',
                'description': 'Unusual conversion volume detected'
            })
            
        if self._is_frequency_anomalous(blockchain_conversions):
            anomalies.append({
                'type': 'frequency',
                'description': 'Unusual conversion frequency detected'
            })
            
        if self._detect_suspicious_patterns(blockchain_conversions, swift_activity):
            anomalies.append({
                'type': 'pattern',
                'description': 'Suspicious conversion pattern detected'
            })
            
        return anomalies
    
    def _is_volume_anomalous(self, conversions: Dict[str, Any]) -> bool:
        """Check if conversion volume is anomalous"""
        volume = conversions.get('volume', 0)
        return volume > self.config.get('MAX_VOLUME_THRESHOLD', 1000000)
    
    def _is_frequency_anomalous(self, conversions: Dict[str, Any]) -> bool:
        """Check if conversion frequency is anomalous"""
        frequency = conversions.get('frequency', 0)
        return frequency > self.config.get('MAX_FREQUENCY_THRESHOLD', 100)
    
    def _detect_suspicious_patterns(self, 
                                   blockchain_conversions: Dict[str, Any],
                                   swift_activity: List[Dict[str, Any]]) -> bool:
        """Detect suspicious conversion patterns"""
        # Implementation of pattern detection
        return False
    
    def get_conversion_rates(self, 
                            from_currency: str, 
                            to_currency: str) -> Dict[str, Any]:
        """Get current conversion rates"""
        try:
            # Get blockchain rate
            blockchain_rate = self.conversion_system._get_blockchain_rate(
                from_currency,
                to_currency
            )
            
            # Get fiat rate
            fiat_rate = self.swift.convert_currency(
                1.0,
                from_currency,
                to_currency
            )['rate']
            
            return {
                'blockchain_rate': blockchain_rate,
                'fiat_rate': fiat_rate,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting conversion rates: {e}")
            raise
