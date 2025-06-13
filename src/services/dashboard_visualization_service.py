"""
Enhanced dashboard visualization service with multiple visualizations.
"""

from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models.security_dashboard import SecurityEvent, NetworkThreat, ThreatLevel, ThreatType
from security.logging.security_logger import SecurityLogger
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

class DashboardVisualizationService:
    def __init__(self, db: Session, config: Dict[str, Any]):
        self.db = db
        self.config = config
        self.logger = SecurityLogger(config)
        
    def get_dashboard_visualizations(self) -> Dict[str, Any]:
        """Get all dashboard visualizations."""
        try:
            return {
                'threat_level_pie': self._get_threat_level_pie(),
                'event_timeline': self._get_event_timeline(),
                'network_traffic': self._get_network_traffic(),
                'geographical_heatmap': self._get_geographical_heatmap(),
                'protocol_distribution': self._get_protocol_distribution(),
                'module_activity': self._get_module_activity(),
                'recent_events': self._get_recent_events()
            }
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='visualization_failed',
                error=str(e)
            )
            raise
    
    def _get_threat_level_pie(self) -> Dict[str, Any]:
        """Get threat level distribution pie chart."""
        # Get threat level counts
        levels = self.db.query(SecurityEvent.threat_level, SecurityEvent.id)
        df = pd.DataFrame(levels, columns=['threat_level', 'count'])
        df = df.groupby('threat_level').count()
        
        # Create pie chart
        fig = px.pie(
            df,
            values='count',
            names=df.index,
            title='Threat Level Distribution'
        )
        
        return {
            'type': 'pie',
            'data': fig.to_dict()
        }
    
    def _get_event_timeline(self) -> Dict[str, Any]:
        """Get event timeline visualization."""
        # Get recent events
        events = self.db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(100)
        df = pd.DataFrame(events)
        
        # Create timeline
        fig = px.timeline(
            df,
            x_start='timestamp',
            x_end='timestamp',
            y='event_type',
            color='threat_level',
            title='Recent Security Events'
        )
        
        return {
            'type': 'timeline',
            'data': fig.to_dict()
        }
    
    def _get_network_traffic(self) -> Dict[str, Any]:
        """Get network traffic visualization."""
        # Get network threats
        threats = self.db.query(NetworkThreat)
        df = pd.DataFrame(threats)
        
        # Create traffic visualization
        fig = px.scatter(
            df,
            x='packet_size',
            y='packet_count',
            color='protocol_stack',
            size='packet_size',
            title='Network Traffic Analysis'
        )
        
        return {
            'type': 'scatter',
            'data': fig.to_dict()
        }
    
    def _get_geographical_heatmap(self) -> Dict[str, Any]:
        """Get geographical threat heatmap."""
        # Get events with location data
        events = self.db.query(SecurityEvent)
        df = pd.DataFrame(events)
        
        # Create heatmap
        fig = px.density_mapbox(
            df,
            lat='latitude',
            lon='longitude',
            z='threat_level',
            radius=10,
            title='Geographical Threat Distribution'
        )
        
        return {
            'type': 'heatmap',
            'data': fig.to_dict()
        }
    
    def _get_protocol_distribution(self) -> Dict[str, Any]:
        """Get protocol distribution bar chart."""
        # Get protocol data
        protocols = self.db.query(NetworkThreat.protocol_stack, NetworkThreat.id)
        df = pd.DataFrame(protocols, columns=['protocol', 'count'])
        df = df.groupby('protocol').count()
        
        # Create bar chart
        fig = px.bar(
            df,
            x=df.index,
            y='count',
            title='Protocol Distribution'
        )
        
        return {
            'type': 'bar',
            'data': fig.to_dict()
        }
    
    def _get_module_activity(self) -> Dict[str, Any]:
        """Get module activity line chart."""
        # Get module data
        modules = self.db.query(SecurityEvent.module, SecurityEvent.timestamp)
        df = pd.DataFrame(modules)
        
        # Create line chart
        fig = px.line(
            df,
            x='timestamp',
            y='module',
            title='Module Activity Over Time'
        )
        
        return {
            'type': 'line',
            'data': fig.to_dict()
        }
    
    def _get_recent_events(self) -> List[Dict[str, Any]]:
        """Get recent events for table display."""
        events = self.db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(50)
        return [{
            'id': event.id,
            'type': event.event_type.value,
            'level': event.threat_level.value,
            'description': event.description,
            'timestamp': event.timestamp.isoformat(),
            'source_ip': event.source_ip,
            'destination_ip': event.destination_ip,
            'module': event.module,
            'function': event.function
        } for event in events]
