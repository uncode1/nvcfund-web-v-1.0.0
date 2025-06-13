from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from models.security_event import SecurityEvent, SecurityEventType, SecurityEventSeverity
from security.logging import SecurityLogger
import json
from collections import defaultdict

class ThreatHunting:
    def __init__(self, logger: SecurityLogger = None):
        self.logger = logger or SecurityLogger()
        self.patterns = self._load_patterns()
        
    def _load_patterns(self) -> Dict[str, Any]:
        """Load threat patterns"""
        return {
            'brute_force': {
                'description': 'Multiple failed login attempts from same IP',
                'pattern': {
                    'event_type': SecurityEventType.LOGIN_FAILURE,
                    'threshold': 5,  # Number of failures
                    'window': timedelta(minutes=15)  # Time window
                }
            },
            'xss_attack': {
                'description': 'Multiple XSS attempts',
                'pattern': {
                    'event_type': SecurityEventType.XSS_ATTEMPT,
                    'threshold': 3,
                    'window': timedelta(minutes=5)
                }
            },
            'sql_injection': {
                'description': 'Multiple SQL injection attempts',
                'pattern': {
                    'event_type': SecurityEventType.SQL_INJECTION,
                    'threshold': 3,
                    'window': timedelta(minutes=5)
                }
            },
            'ip_suspicious': {
                'description': 'Multiple suspicious activities from same IP',
                'pattern': {
                    'event_types': [
                        SecurityEventType.XSS_ATTEMPT,
                        SecurityEventType.SQL_INJECTION,
                        SecurityEventType.CSRF_ATTACK,
                        SecurityEventType.RCE_ATTEMPT
                    ],
                    'threshold': 3,
                    'window': timedelta(minutes=10)
                }
            }
        }
    
    def analyze_events(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Analyze security events for potential threats"""
        threats = []
        
        # Group events by IP and event type
        events_by_ip = defaultdict(lambda: defaultdict(list))
        for event in events:
            events_by_ip[event.source_ip][event.event_type].append(event)
            
        # Check each threat pattern
        for threat_name, pattern in self.patterns.items():
            if 'event_type' in pattern:
                self._check_single_event_type_threat(threat_name, pattern, events_by_ip, threats)
            else:
                self._check_multiple_event_types_threat(threat_name, pattern, events_by_ip, threats)
                
        return threats
    
    def _check_single_event_type_threat(self, threat_name: str, 
                                      pattern: Dict[str, Any], 
                                      events_by_ip: Dict[str, Dict[SecurityEventType, List[SecurityEvent]]], 
                                      threats: List[Dict[str, Any]]):
        """Check for threats with a single event type"""
        for ip, event_types in events_by_ip.items():
            events = event_types.get(pattern['event_type'], [])
            if len(events) >= pattern['threshold']:
                # Check if events are within time window
                if self._events_within_window(events, pattern['window']):
                    threat = {
                        'threat_name': threat_name,
                        'description': pattern['description'],
                        'ip': ip,
                        'event_count': len(events),
                        'first_event': events[0].timestamp,
                        'last_event': events[-1].timestamp,
                        'events': [e.to_dict() for e in events]
                    }
                    threats.append(threat)
    
    def _check_multiple_event_types_threat(self, threat_name: str, 
                                         pattern: Dict[str, Any], 
                                         events_by_ip: Dict[str, Dict[SecurityEventType, List[SecurityEvent]]], 
                                         threats: List[Dict[str, Any]]):
        """Check for threats with multiple event types"""
        for ip, event_types in events_by_ip.items():
            total_events = []
            for event_type in pattern['event_types']:
                total_events.extend(event_types.get(event_type, []))
                
            if len(total_events) >= pattern['threshold']:
                # Check if events are within time window
                if self._events_within_window(total_events, pattern['window']):
                    threat = {
                        'threat_name': threat_name,
                        'description': pattern['description'],
                        'ip': ip,
                        'event_count': len(total_events),
                        'first_event': min(e.timestamp for e in total_events),
                        'last_event': max(e.timestamp for e in total_events),
                        'events': [e.to_dict() for e in total_events]
                    }
                    threats.append(threat)
    
    def _events_within_window(self, events: List[SecurityEvent], window: timedelta) -> bool:
        """Check if events are within time window"""
        if not events:
            return False
            
        first_event = min(events, key=lambda e: e.timestamp)
        last_event = max(events, key=lambda e: e.timestamp)
        
        return (last_event.timestamp - first_event.timestamp) <= window
    
    def detect_anomalies(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Detect anomalies in security events"""
        anomalies = []
        
        # Group events by IP
        events_by_ip = defaultdict(list)
        for event in events:
            events_by_ip[event.source_ip].append(event)
            
        # Check for anomalies
        for ip, ip_events in events_by_ip.items():
            self._check_anomalies_for_ip(ip, ip_events, anomalies)
            
        return anomalies
    
    def _check_anomalies_for_ip(self, ip: str, 
                              events: List[SecurityEvent], 
                              anomalies: List[Dict[str, Any]]):
        """Check for anomalies for a specific IP"""
        # Check for unusual activity patterns
        if self._check_unusual_activity_pattern(events):
            anomaly = {
                'type': 'unusual_activity',
                'ip': ip,
                'description': 'Unusual activity pattern detected',
                'events': [e.to_dict() for e in events]
            }
            anomalies.append(anomaly)
            
        # Check for rapid request rate
        if self._check_rapid_request_rate(events):
            anomaly = {
                'type': 'rapid_requests',
                'ip': ip,
                'description': 'Rapid request rate detected',
                'events': [e.to_dict() for e in events]
            }
            anomalies.append(anomaly)
    
    def _check_unusual_activity_pattern(self, events: List[SecurityEvent]) -> bool:
        """Check for unusual activity patterns"""
        # Implementation of activity pattern analysis
        return False
    
    def _check_rapid_request_rate(self, events: List[SecurityEvent]) -> bool:
        """Check for rapid request rate"""
        # Implementation of request rate analysis
        return False
    
    def generate_threat_report(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate a threat hunting report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_events': len(events),
            'threats': self.analyze_events(events),
            'anomalies': self.detect_anomalies(events),
            'summary': self._generate_summary(events)
        }
        
        return report
    
    def _generate_summary(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate summary statistics"""
        summary = {
            'event_count': len(events),
            'event_types': defaultdict(int),
            'severity_distribution': defaultdict(int),
            'ip_distribution': defaultdict(int)
        }
        
        for event in events:
            summary['event_types'][event.event_type.value] += 1
            summary['severity_distribution'][event.severity.value] += 1
            summary['ip_distribution'][event.source_ip] += 1
            
        return dict(summary)
