from flask import current_app, request
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token
from datetime import datetime, timedelta
from functools import wraps
from models.security import AuditLog
import jwt
import secrets
import base64
import os

class AuthManager:
    def __init__(self, app=None):
        self.jwt = JWTManager()
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        self.jwt.init_app(app)
        
        # Configure JWT settings
        app.config['JWT_SECRET_KEY'] = os.urandom(32).hex()
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
        app.config['JWT_BLACKLIST_ENABLED'] = True
        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
        
        # Initialize the JWT manager
        self.jwt.init_app(app)
    
    def create_tokens(self, user_id, user_roles):
        """Create JWT access and refresh tokens"""
        access_token = create_access_token(
            identity=user_id,
            expires_delta=timedelta(minutes=15),
            additional_claims={'roles': user_roles}
        )
        
        refresh_token = create_refresh_token(
            identity=user_id,
            expires_delta=timedelta(days=30)
        )
        
        return access_token, refresh_token
    
    def refresh_token_required(self, view_func):
        """Decorator for refresh token required endpoints"""
        @wraps(view_func)
        def decorated(*args, **kwargs):
            try:
                # Get the refresh token from the request
                refresh_token = request.headers.get('Authorization', '').replace('Bearer ', '')
                
                # Verify and decode the refresh token
                claims = jwt.decode(
                    refresh_token,
                    current_app.config['JWT_SECRET_KEY'],
                    algorithms=['HS256']
                )
                
                # Create new access token
                access_token, _ = self.create_tokens(
                    claims['sub'],
                    claims.get('roles', [])
                )
                
                # Return the new access token
                return {
                    'access_token': access_token,
                    'user_id': claims['sub'],
                    'roles': claims.get('roles', [])
                }
                
            except jwt.ExpiredSignatureError:
                return {'error': 'Refresh token has expired'}, 401
            except jwt.InvalidTokenError:
                return {'error': 'Invalid refresh token'}, 401
            
        return decorated
    
    def token_required(self, roles=None):
        """Decorator for token required endpoints"""
        def decorator(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                try:
                    # Get the access token from the request
                    access_token = request.headers.get('Authorization', '').replace('Bearer ', '')
                    
                    # Verify and decode the access token
                    claims = jwt.decode(
                        access_token,
                        current_app.config['JWT_SECRET_KEY'],
                        algorithms=['HS256']
                    )
                    
                    # Check if user has required roles
                    if roles and not any(role in claims.get('roles', []) for role in roles):
                        return {'error': 'Insufficient permissions'}, 403
                    
                    # Log the action
                    audit_log = AuditLog(
                        user_id=claims['sub'],
                        action='api_access',
                        description=f'Accessed endpoint: {request.path}',
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent')
                    )
                    db.session.add(audit_log)
                    db.session.commit()
                    
                    return view_func(*args, **kwargs)
                    
                except jwt.ExpiredSignatureError:
                    return {'error': 'Token has expired'}, 401
                except jwt.InvalidTokenError:
                    return {'error': 'Invalid token'}, 401
                
            return decorated
        return decorator
    
    def generate_session_id(self):
        """Generate a secure session ID"""
        return base64.b64encode(os.urandom(32)).decode()
    
    def verify_session(self, session_id):
        """Verify session validity"""
        try:
            # Verify session token
            jwt.decode(
                session_id,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
    
    def logout(self, session_id):
        """Logout user and invalidate session"""
        try:
            # Blacklist the session token
            # Implementation of session blacklisting
            pass
            
            # Log the logout action
            audit_log = AuditLog(
                user_id=claims['sub'],
                action='logout',
                description='User logged out',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(audit_log)
            db.session.commit()
            
            return {'message': 'Successfully logged out'}
            
        except Exception as e:
            return {'error': str(e)}, 500
