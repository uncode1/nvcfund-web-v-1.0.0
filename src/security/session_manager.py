from flask import session
from datetime import datetime, timedelta
import secrets
import base64
import os
from models.security import AuditLog

class SessionManager:
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        
        # Configure session settings
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
        app.config['SESSION_REFRESH_EACH_REQUEST'] = True
        
        # Generate secure session key
        app.secret_key = os.urandom(32)
    
    def create_session(self, user_id, user_roles):
        """Create a new session"""
        # Generate secure session ID
        session_id = base64.b64encode(os.urandom(32)).decode()
        
        # Store session data
        session['user_id'] = user_id
        session['roles'] = user_roles
        session['session_id'] = session_id
        session['created_at'] = datetime.utcnow()
        session.permanent = True
        
        # Log the session creation
        audit_log = AuditLog(
            user_id=user_id,
            action='session_create',
            description='New session created',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return session_id
    
    def refresh_session(self):
        """Refresh the current session"""
        if 'user_id' not in session:
            return False
            
        # Update session creation time
        session['created_at'] = datetime.utcnow()
        
        # Log the session refresh
        audit_log = AuditLog(
            user_id=session['user_id'],
            action='session_refresh',
            description='Session refreshed',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return True
    
    def verify_session(self):
        """Verify session validity"""
        if 'user_id' not in session:
            return False
            
        # Check session age
        session_age = datetime.utcnow() - session.get('created_at', datetime.utcnow())
        if session_age > timedelta(minutes=15):
            return False
            
        # Check for session tampering
        if session.get('session_id') != request.cookies.get('session_id'):
            return False
            
        return True
    
    def terminate_session(self):
        """Terminate the current session"""
        if 'user_id' in session:
            # Log the session termination
            audit_log = AuditLog(
                user_id=session['user_id'],
                action='session_terminate',
                description='Session terminated',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(audit_log)
            db.session.commit()
            
        # Clear session data
        session.clear()
    
    def session_required(self, roles=None):
        """Decorator for session required endpoints"""
        def decorator(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                if not self.verify_session():
                    return {'error': 'Session expired'}, 401
                    
                # Check if user has required roles
                if roles and not any(role in session.get('roles', []) for role in roles):
                    return {'error': 'Insufficient permissions'}, 403
                    
                self.refresh_session()
                return view_func(*args, **kwargs)
                
            return decorated
        return decorator
    
    def secure_session_cookie(self):
        """Configure secure session cookie"""
        @self.app.after_request
        def apply_secure_cookie(response):
            if 'session_id' in session:
                response.set_cookie(
                    'session_id',
                    session['session_id'],
                    secure=True,
                    httponly=True,
                    samesite='Lax',
                    max_age=timedelta(minutes=15)
                )
            return response
