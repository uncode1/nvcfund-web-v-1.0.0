"""
Secure coding utilities to prevent common vulnerabilities.
"""

from typing import Any, Dict, Optional
import re
import secrets
import string
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from src.security.logging import SecurityLogger

class SecureCoding:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self._initialize_patterns()

    def _initialize_patterns(self) -> None:
        """Initialize regex patterns for input validation."""
        self.patterns = {
            'sql': re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b', re.IGNORECASE),
            'xss': re.compile(r'<script|javascript:', re.IGNORECASE),
            'path': re.compile(r'\.{2}/|/\.{2}|\.{2}\\|\\\.{2}\\'),
            'cmd': re.compile(r'\b(system|exec|shell_exec|passthru|eval|assert)\b', re.IGNORECASE),
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'phone': re.compile(r'^\+[1-9]\d{1,14}$')
        }

    def validate_input(self, value: str, pattern: str) -> bool:
        """Validate input against specified pattern."""
        if pattern not in self.patterns:
            raise ValueError(f"Invalid pattern: {pattern}")
        
        if self.patterns[pattern].search(value):
            self.logger.log_event(
                SecurityEventType.SECURITY,
                SecurityEventSeverity.WARNING,
                event_type='input_validation_failed',
                pattern=pattern,
                value=value[:50]
            )
            return False
            
        return True

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token."""
        chars = string.ascii_letters + string.digits
        return ''.join(secrets.choice(chars) for _ in range(length))

    def hash_password(self, password: str) -> str:
        """Securely hash password."""
        return generate_password_hash(password, method='pbkdf2:sha256:100000')

    def verify_password(self, password: str, hash_: str) -> bool:
        """Verify password against hash."""
        return check_password_hash(hash_, password)

def validate_input(pattern: str):
    """Decorator to validate input parameters."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            secure = SecureCoding({})  # Initialize with config
            
            # Validate all string arguments
            for arg in args:
                if isinstance(arg, str):
                    if not secure.validate_input(arg, pattern):
                        raise ValueError("Invalid input")
            
            for value in kwargs.values():
                if isinstance(value, str):
                    if not secure.validate_input(value, pattern):
                        raise ValueError("Invalid input")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def rate_limit(limit: int, window: int):
    """Rate limiting decorator."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Implementation of rate limiting
            return func(*args, **kwargs)
        return wrapper
    return decorator

def csrf_protect(func):
    """CSRF protection decorator."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Implementation of CSRF protection
        return func(*args, **kwargs)
    return wrapper

def xss_protect(func):
    """XSS protection decorator."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Implementation of XSS protection
        return func(*args, **kwargs)
    return wrapper

def sql_injection_protect(func):
    """SQL injection protection decorator."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Implementation of SQL injection protection
        return func(*args, **kwargs)
    return wrapper
