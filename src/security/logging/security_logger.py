from typing import Dict, Any, Optional
import logging
from enum import Enum
from datetime import datetime
from security.threat_hunting.threat_hunter import ThreatHunter
from security.aml.aml_analyzer import AMLAnalyzer
from security.fraud_detection.fraud_detector import FraudDetector

class SecurityEventType(Enum):
    AUTHENTICATION = 'authentication'
    AUTHORIZATION = 'authorization'
    AUDIT = 'audit'
    ERROR = 'error'
    SECURITY = 'security'
    SYSTEM = 'system'
    MAINTENANCE = 'maintenance'

class SecurityEventSeverity(Enum):
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'

class SecurityLogger:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('security')
        self.threat_hunter = ThreatHunter()
        self.aml_analyzer = AMLAnalyzer()
        self.fraud_detector = FraudDetector()
        
        # Configure logger
        self._configure_logger()
        
    def _configure_logger(self):
        """Configure security logger"""
        self.logger.setLevel(logging.INFO)
        
        # Create file handler
        file_handler = logging.FileHandler(self.config.get('SECURITY_LOG_FILE', 'security.log'))
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        
    def log_event(self, 
                 event_type: SecurityEventType, 
                 severity: SecurityEventSeverity, 
                 **kwargs) -> None:
        """Log security event"""
        try:
            # Create event data
            event_data = {
                'event_type': event_type.value,
                'severity': severity.value,
                'timestamp': datetime.now().isoformat(),
                **kwargs
            }
            
            # Analyze event for threats
            threat_level = self.threat_hunter.analyze_event(event_data)
            
            # Check for AML concerns
            aml_risk = self.aml_analyzer.analyze_event(event_data)
            
            # Check for fraud patterns
            fraud_score = self.fraud_detector.analyze_event(event_data)
            
            # Log event
            self.logger.log(
                logging.INFO,
                f"Security Event: {event_data}"
            )
            
            # If high risk, generate alert
            if threat_level >= 0.8 or aml_risk >= 0.8 or fraud_score >= 0.8:
                self._generate_security_alert(event_data, threat_level, aml_risk, fraud_score)
                
        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")
            raise
    
    def _generate_security_alert(self, 
                               event_data: Dict[str, Any],
                               threat_level: float,
                               aml_risk: float,
                               fraud_score: float) -> None:
        """Generate security alert for high-risk events"""
        alert_data = {
            'event_data': event_data,
            'threat_level': threat_level,
            'aml_risk': aml_risk,
            'fraud_score': fraud_score,
            'timestamp': datetime.now().isoformat()
        }
        
        self.logger.log(
            logging.CRITICAL,
            f"Security Alert: {alert_data}"
        )
        
    def log_authentication(self, 
                          user_id: str,
                          success: bool,
                          details: Optional[Dict[str, Any]] = None) -> None:
        """Log authentication event"""
        self.log_event(
            SecurityEventType.AUTHENTICATION,
            SecurityEventSeverity.INFO if success else SecurityEventSeverity.ERROR,
            user_id=user_id,
            success=success,
            details=details or {}
        )
        
    def log_authorization(self, 
                         user_id: str,
                         resource: str,
                         action: str,
                         success: bool) -> None:
        """Log authorization event"""
        self.log_event(
            SecurityEventType.AUTHORIZATION,
            SecurityEventSeverity.INFO if success else SecurityEventSeverity.ERROR,
            user_id=user_id,
            resource=resource,
            action=action,
            success=success
        )
        
    def log_security_event(self, 
                          event_type: str,
                          details: Dict[str, Any]) -> None:
        """Log generic security event"""
        self.log_event(
            SecurityEventType.SECURITY,
            SecurityEventSeverity.INFO,
            event_type=event_type,
            details=details
        )
        
    def log_system_event(self, 
                        event_type: str,
                        details: Dict[str, Any]) -> None:
        """Log system event"""
        self.log_event(
            SecurityEventType.SYSTEM,
            SecurityEventSeverity.INFO,
            event_type=event_type,
            details=details
        )
