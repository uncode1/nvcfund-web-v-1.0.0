from typing import Dict, Any, Optional
from flask import Flask, g
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token
from security.logging.security_logger import SecurityLogger
from security.session.session_manager import SessionManager

class AuthManager:
    def __init__(self, app: Flask, config: Dict[str, Any]):
        self.app = app
        self.config = config
        self.jwt = JWTManager(app)
        self.logger = SecurityLogger(config)
        self.session_manager = SessionManager(config)
        
    def init_app(self, app: Flask):
        """Initialize authentication"""
        self.jwt.init_app(app)
        
        # Add JWT callbacks
        @self.jwt.token_in_blocklist_loader
        def check_if_token_is_revoked(jwt_header, jwt_payload):
            return self._is_token_revoked(jwt_payload)
            
        @self.jwt.user_identity_loader
        def user_identity_lookup(user):
            return user.id
            
        @self.jwt.user_lookup_loader
        def user_lookup_callback(_jwt_header, jwt_data):
            return self._get_user(jwt_data["sub"])
            
    def create_access_token(self, identity: Any, additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """Create access token"""
        try:
            token = create_access_token(
                identity=identity,
                additional_claims=additional_claims,
                expires_delta=self.config.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
            )
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='token_creation',
                token_type='access',
                user_id=str(identity)
            )
            return token
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='token_creation_failed',
                error=str(e)
            )
            raise
    
    def create_refresh_token(self, identity: Any) -> str:
        """Create refresh token"""
        try:
            token = create_refresh_token(
                identity=identity,
                expires_delta=self.config.get('JWT_REFRESH_TOKEN_EXPIRES', 86400)
            )
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='token_creation',
                token_type='refresh',
                user_id=str(identity)
            )
            return token
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='token_creation_failed',
                error=str(e)
            )
            raise
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token"""
        try:
            from flask_jwt_extended import decode_token
            
            decoded_token = decode_token(token)
            
            # Check if token is revoked
            if self._is_token_revoked(decoded_token):
                raise ValueError("Token has been revoked")
                
            # Check if token is expired
            if decoded_token['exp'] < datetime.now().timestamp():
                raise ValueError("Token has expired")
                
            return decoded_token
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='token_verification_failed',
                error=str(e)
            )
            raise
    
    def revoke_token(self, token: str) -> None:
        """Revoke JWT token"""
        try:
            from flask_jwt_extended import decode_token
            
            decoded_token = decode_token(token)
            self.session_manager.revoke_token(decoded_token['jti'])
            
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='token_revoked',
                token_type=decoded_token['type'],
                user_id=decoded_token['sub']
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='token_revocation_failed',
                error=str(e)
            )
            raise
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token"""
        try:
            from flask_jwt_extended import decode_token
            
            decoded_token = decode_token(refresh_token)
            
            if decoded_token['type'] != 'refresh':
                raise ValueError("Invalid token type")
                
            # Create new access token
            new_token = self.create_access_token(
                identity=decoded_token['sub'],
                additional_claims={'refresh_token': refresh_token}
            )
            
            return {
                'access_token': new_token,
                'refresh_token': refresh_token
            }
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='token_refresh_failed',
                error=str(e)
            )
            raise
    
    def _is_token_revoked(self, token: Dict[str, Any]) -> bool:
        """Check if token is revoked"""
        return self.session_manager.is_token_revoked(token['jti'])
    
    def _get_user(self, user_id: str) -> Any:
        """Get user by ID"""
        # Implementation of user retrieval
        return None
