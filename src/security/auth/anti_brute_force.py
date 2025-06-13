from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from security.logging.security_logger import SecurityLogger

class AntiBruteForce:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self.login_attempts = {}
        self.locked_accounts = {}
        
    def validate_login_attempt(self, username: str, ip_address: str) -> bool:
        """Validate login attempt"""
        try:
            # Check if account is locked
            if self._is_account_locked(username):
                return False
                
            # Track login attempt
            self._track_login_attempt(username, ip_address)
            
            # Check rate limits
            if self._exceeds_rate_limit(username, ip_address):
                self._lock_account(username)
                return False
                
            return True
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='brute_force_validation_failed',
                error=str(e)
            )
            return False
    
    def _track_login_attempt(self, username: str, ip_address: str) -> None:
        """Track login attempt"""
        now = datetime.now()
        
        # Track per username
        if username not in self.login_attempts:
            self.login_attempts[username] = []
        self.login_attempts[username].append((ip_address, now))
        
        # Clean up old attempts
        self._cleanup_old_attempts(username)
        
        # Track per IP
        if ip_address not in self.login_attempts:
            self.login_attempts[ip_address] = []
        self.login_attempts[ip_address].append((username, now))
        
        # Clean up old attempts
        self._cleanup_old_attempts(ip_address)
    
    def _cleanup_old_attempts(self, key: str) -> None:
        """Clean up old login attempts"""
        if key in self.login_attempts:
            self.login_attempts[key] = [
                attempt for attempt in self.login_attempts[key]
                if attempt[1] > datetime.now() - timedelta(minutes=30)
            ]
    
    def _exceeds_rate_limit(self, username: str, ip_address: str) -> bool:
        """Check if rate limit is exceeded"""
        # Get recent attempts
        username_attempts = self.login_attempts.get(username, [])
        ip_attempts = self.login_attempts.get(ip_address, [])
        
        # Check username rate limit
        if len(username_attempts) >= self.config.get('MAX_LOGIN_ATTEMPTS', 5):
            return True
            
        # Check IP rate limit
        if len(ip_attempts) >= self.config.get('MAX_IP_ATTEMPTS', 10):
            return True
            
        return False
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked"""
        if username not in self.locked_accounts:
            return False
            
        lock_time = self.locked_accounts[username]
        if datetime.now() - lock_time > timedelta(hours=1):
            # Unlock account after 1 hour
            del self.locked_accounts[username]
            return False
            
        return True
    
    def _lock_account(self, username: str) -> None:
        """Lock account due to too many failed attempts"""
        self.locked_accounts[username] = datetime.now()
        self.logger.log_event(
            SecurityEventType.AUTHENTICATION,
            SecurityEventSeverity.CRITICAL,
            event_type='account_locked',
            username=username,
            reason='too_many_attempts'
        )
    
    def unlock_account(self, username: str) -> None:
        """Unlock account"""
        if username in self.locked_accounts:
            del self.locked_accounts[username]
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='account_unlocked',
                username=username
            )
    
    def get_login_stats(self, username: str) -> Dict[str, Any]:
        """Get login statistics"""
        return {
            'attempts': len(self.login_attempts.get(username, [])),
            'locked': username in self.locked_accounts,
            'last_attempt': self.login_attempts.get(username, [])[-1][1] if self.login_attempts.get(username) else None
        }
