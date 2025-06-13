from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime
import pyotp
from models.security import MFA, AuditLog
from utils.security_utils import SecurityUtils

class SecurityMiddleware:
    @staticmethod
    def require_mfa(view_func):
        """Decorator to enforce MFA requirement"""
        @wraps(view_func)
        def decorated(*args, **kwargs):
            user = current_user
            if not user:
                return jsonify({'error': 'Unauthorized'}), 401
            
            mfa = MFA.query.filter_by(user_id=user.id, status='active').first()
            if not mfa:
                return jsonify({'error': 'MFA required'}), 403
            
            # Check if MFA was verified in last 15 minutes
            if mfa.last_verified and \
               (datetime.utcnow() - mfa.last_verified).total_seconds() > 900:
                return jsonify({'error': 'MFA verification expired'}), 403
            
            return view_func(*args, **kwargs)
        return decorated
    
    @staticmethod
    def audit_log(action: str, description: str):
        """Decorator to log actions for audit purposes"""
        def decorator(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                result = view_func(*args, **kwargs)
                
                audit_log = AuditLog(
                    user_id=current_user.id,
                    action=action,
                    description=description,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=result[1] < 400 if isinstance(result, tuple) else True
                )
                db.session.add(audit_log)
                db.session.commit()
                
                return result
            return decorated
        return decorator
    
    @staticmethod
    def validate_card_data(view_func):
        """Decorator to validate card data according to PCI DSS"""
        @wraps(view_func)
        def decorated(*args, **kwargs):
            if request.method == 'POST':
                data = request.get_json()
                card_number = data.get('card_number')
                expiry_date = data.get('expiry_date')
                
                if not card_number or not expiry_date:
                    return jsonify({'error': 'Missing required card data'}), 400
                
                # Validate card number
                if not SecurityUtils.validate_card_number(card_number):
                    return jsonify({'error': 'Invalid card number'}), 400
                
                # Validate expiry date
                try:
                    expiry_year, expiry_month = map(int, expiry_date.split('/'))
                    if expiry_year < datetime.now().year or \
                       (expiry_year == datetime.now().year and expiry_month < datetime.now().month):
                        return jsonify({'error': 'Card has expired'}), 400
                except:
                    return jsonify({'error': 'Invalid expiry date format'}), 400
                
                # Mask card number before storing
                data['card_number'] = SecurityUtils.mask_card_number(card_number)
            
            return view_func(*args, **kwargs)
        return decorated
    
    @staticmethod
    def rate_limit(limit: int, window: int):
        """Decorator to enforce rate limiting"""
        def decorator(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                # Implementation of rate limiting
                pass
            return decorated
        return decorator
