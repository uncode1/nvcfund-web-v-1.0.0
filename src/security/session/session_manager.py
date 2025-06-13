from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from security.logging.security_logger import SecurityLogger

class SessionManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self.sessions = {}  # In-memory session storage
        self.revoked_tokens = set()
        
    def create_session(self, user_id: str) -> Dict[str, Any]:
        """Create new session"""
        try:
            session_id = self._generate_session_id()
            session_data = {
                'user_id': user_id,
                'created_at': datetime.now(),
                'last_activity': datetime.now(),
                'status': 'active'
            }
            
            self.sessions[session_id] = session_data
            
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='session_creation',
                session_id=session_id,
                user_id=user_id
            )
            
            return {
                'session_id': session_id,
                'data': session_data
            }
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='session_creation_failed',
                error=str(e)
            )
            raise
    
    def verify_session(self, session_id: str) -> Dict[str, Any]:
        """Verify session validity"""
        try:
            if session_id not in self.sessions:
                raise ValueError("Session not found")
                
            session = self.sessions[session_id]
            
            # Check session expiration
            if datetime.now() - session['created_at'] > timedelta(hours=24):
                raise ValueError("Session expired")
                
            # Update last activity
            session['last_activity'] = datetime.now()
            
            return session
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='session_verification_failed',
                error=str(e)
            )
            raise
    
    def terminate_session(self, session_id: str) -> None:
        """Terminate session"""
        try:
            if session_id in self.sessions:
                del self.sessions[session_id]
                
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='session_terminated',
                session_id=session_id
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='session_termination_failed',
                error=str(e)
            )
            raise
    
    def revoke_token(self, token_id: str) -> None:
        """Revoke JWT token"""
        try:
            self.revoked_tokens.add(token_id)
            
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='token_revoked',
                token_id=token_id
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='token_revocation_failed',
                error=str(e)
            )
            raise
    
    def is_token_revoked(self, token_id: str) -> bool:
        """Check if token is revoked"""
        return token_id in self.revoked_tokens
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        import uuid
        return str(uuid.uuid4())
    
    def cleanup_sessions(self) -> None:
        """Clean up expired sessions"""
        try:
            now = datetime.now()
            expired_sessions = []
            
            for session_id, session in list(self.sessions.items()):
                if now - session['created_at'] > timedelta(hours=24):
                    expired_sessions.append(session_id)
                    
            for session_id in expired_sessions:
                del self.sessions[session_id]
                
            self.logger.log_event(
                SecurityEventType.MAINTENANCE,
                SecurityEventSeverity.INFO,
                event_type='session_cleanup',
                expired_count=len(expired_sessions)
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='session_cleanup_failed',
                error=str(e)
            )
            raise
