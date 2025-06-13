from flask import Blueprint, jsonify, request
from src.services.security_dashboard_service import SecurityDashboardService
from src.services.notification_service import NotificationService
from src.models.security_dashboard import ThreatLevel, ThreatType
from src.security.auth.auth_manager import AuthManager
from src.security.web.web_security import WebSecurity

security_dashboard_bp = Blueprint('security_dashboard', __name__)

def get_security_dashboard_service():
    """Get security dashboard service instance"""
    # Implementation to get service instance
    return SecurityDashboardService()

def get_auth_manager():
    """Get auth manager instance"""
    # Implementation to get auth manager
    return AuthManager()

def get_web_security():
    """Get web security instance"""
    # Implementation to get web security
    return WebSecurity()

@security_dashboard_bp.route('/api/security/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get security dashboard statistics"""
    try:
        service = get_security_dashboard_service()
        stats = service.get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_dashboard_bp.route('/api/security/events', methods=['GET'])
def get_security_events():
    """Get security events"""
    try:
        service = get_security_dashboard_service()
        events = service.get_recent_events()
        return jsonify(events)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_dashboard_bp.route('/api/security/events', methods=['POST'])
def log_security_event():
    """Log security event"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['event_type', 'threat_level', 'description', 
                         'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Create event
        service = get_security_dashboard_service()
        event = service.log_security_event(
            event_type=ThreatType[data['event_type'].upper()],
            threat_level=ThreatLevel[data['threat_level'].upper()],
            description=data['description'],
            details=data.get('details', {}),
            source_ip=data['source_ip'],
            source_port=data['source_port'],
            destination_ip=data['destination_ip'],
            destination_port=data['destination_port'],
            protocol=data['protocol'],
            user_id=data.get('user_id'),
            module=data.get('module', ''),
            function=data.get('function', '')
        )
        
        return jsonify({'event_id': event.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_dashboard_bp.route('/api/security/events/<int:event_id>', methods=['PUT'])
def update_event_status(event_id: int):
    """Update event status"""
    try:
        service = get_security_dashboard_service()
        data = request.json
        
        # Update event status
        event = service.update_event_status(event_id, data.get('status', 'resolved'),
                                         data.get('resolution_notes', ''))
        
        return jsonify({'event_id': event.id, 'status': event.status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_dashboard_bp.route('/api/security/alerts/preferences', methods=['GET', 'POST'])
def manage_alert_preferences():
    """Manage alert preferences"""
    try:
        auth_manager = get_auth_manager()
        user = auth_manager.get_current_user()
        
        if request.method == 'GET':
            # Get preferences
            service = get_security_dashboard_service()
            preferences = service.get_alert_preferences(user.id)
            return jsonify(preferences)
            
        elif request.method == 'POST':
            # Update preferences
            data = request.json
            service = get_security_dashboard_service()
            preferences = service.update_alert_preferences(user.id, data)
            return jsonify(preferences)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_dashboard_bp.route('/api/security/network/stats', methods=['GET'])
def get_network_stats():
    """Get network security statistics"""
    try:
        service = get_security_dashboard_service()
        stats = service.get_network_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
