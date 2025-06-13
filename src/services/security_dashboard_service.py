from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from src.models.security_dashboard import SecurityDashboardEvent, NetworkThreat, ThreatLevel, ThreatType
Ensureefrom src.services.notification_service import NotificationService
from security.logging.security_logger import SecurityLogger

class SecurityDashboardService:
    def __init__(self, db: Session, config: Dict[str, Any]):
        self.db = db
        self.config = config
        self.logger = SecurityLogger(config)
        self.notification_service = NotificationService(config)
        
    def log_security_event(self, 
                         event_type: ThreatType,
                         threat_level: ThreatLevel,
                         description: str,
                         details: Dict[str, Any],
                         source_ip: str,
                         source_port: int,
                         destination_ip: str,
                         destination_port: int,
                         protocol: str,
                         user_id: Optional[int] = None,
                         module: str = '',
                         function: str = '') -> SecurityEvent:
        """Log security event with network details"""
        try:
            # Create security event
            event = SecurityEvent(
                event_type=event_type,
                threat_level=threat_level,
                description=description,
                details=str(details),
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol,
                user_id=user_id,
                module=module,
                function=function
            )
            
            # Create network threat record
            network_threat = NetworkThreat(
                event=event,
                protocol_stack=self._get_protocol_stack(protocol),
                packet_size=details.get('packet_size', 0),
                packet_count=details.get('packet_count', 1),
                flags=details.get('flags', ''),
                ttl=details.get('ttl', 0),
                checksum=details.get('checksum', ''),
                sequence_number=details.get('sequence_number', 0)
            )
            
            # Add to database
            self.db.add(event)
            self.db.add(network_threat)
            self.db.commit()
            
            # Send notifications if threat level is high or critical
            if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                self._send_notifications(event)
            
            self.logger.log_event(
                SecurityEventType.SECURITY,
                SecurityEventSeverity.INFO,
                event_type='security_event_logged',
                threat_level=threat_level.value,
                event_type=event_type.value
            )
            
            return event
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='security_event_failed',
                error=str(e)
            )
            raise
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get security dashboard statistics"""
        try:
            # Get threat levels count
            threat_levels = self._get_threat_levels_count()
            
            # Get recent events
            recent_events = self._get_recent_events()
            
            # Get network threats
            network_stats = self._get_network_stats()
            
            # Get module-wise threats
            module_stats = self._get_module_stats()
            
            return {
                'threat_levels': threat_levels,
                'recent_events': recent_events,
                'network_stats': network_stats,
                'module_stats': module_stats,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='dashboard_stats_failed',
                error=str(e)
            )
            raise
    
    def _get_threat_levels_count(self) -> Dict[str, int]:
        """Get count of events by threat level"""
        return {
            'low': self.db.query(SecurityEvent).filter_by(threat_level=ThreatLevel.LOW).count(),
            'medium': self.db.query(SecurityEvent).filter_by(threat_level=ThreatLevel.MEDIUM).count(),
            'high': self.db.query(SecurityEvent).filter_by(threat_level=ThreatLevel.HIGH).count(),
            'critical': self.db.query(SecurityEvent).filter_by(threat_level=ThreatLevel.CRITICAL).count()
        }
    
    def _get_recent_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent security events"""
        events = self.db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
        return [self._format_event(event) for event in events]
    
    def _get_network_stats(self) -> Dict[str, Any]:
        """Get network threat statistics"""
        return {
            'total_threats': self.db.query(NetworkThreat).count(),
            'protocols': self._get_protocol_stats(),
            'top_attackers': self._get_top_attackers(),
            'top_targets': self._get_top_targets()
        }
    
    def _get_module_stats(self) -> Dict[str, int]:
        """Get count of events by module"""
        modules = self.db.query(SecurityEvent.module, SecurityEvent.threat_level)
        stats = {}
        for module, threat_level in modules:
            if module not in stats:
                stats[module] = {level.value: 0 for level in ThreatLevel}
            stats[module][threat_level.value] += 1
        return stats
    
    def _send_notifications(self, event: SecurityEvent) -> None:
        """Send notifications for high priority events"""
        # Get affected users
        users = self._get_affected_users(event)
        
        # Send notifications
        for user in users:
            self.notification_service.send_notification(user.id, {
                'threat_level': event.threat_level,
                'event_type': event.event_type,
                'module': event.module,
                'function': event.function,
                'description': event.description,
                'details': event.details,
                'timestamp': event.timestamp.isoformat(),
                'source_ip': event.source_ip,
                'destination_ip': event.destination_ip
            })
    
    def _get_affected_users(self, event: SecurityEvent) -> List[User]:
        """Get users who should receive notifications"""
        # Implementation to get affected users based on event type and severity
        return []
    
    def _get_protocol_stack(self, protocol: str) -> str:
        """Get OSI/TCP-IP protocol stack"""
        # Implementation to get protocol stack
        return protocol
    
    def _format_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Format event for dashboard display"""
        return {
            'id': event.id,
            'type': event.event_type.value,
            'level': event.threat_level.value,
            'description': event.description,
            'timestamp': event.timestamp.isoformat(),
            'source_ip': event.source_ip,
            'destination_ip': event.destination_ip,
            'module': event.module,
            'function': event.function
        }
    
    def _get_protocol_stats(self) -> Dict[str, int]:
        """Get statistics by protocol"""
        return {}
    
    def _get_top_attackers(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get top attacking IPs"""
        return []
    
    def _get_top_targets(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get top targeted IPs"""
        return []
