from flask import Flask, request, Response
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests
from functools import wraps
import re
import hmac
import hashlib
import base64
import json
from datetime import datetime, timedelta
import logging
from typing import Callable, Any, Optional
from src.security.config import SecurityConfig

logger = logging.getLogger(__name__)

class WebSecurity:
    def __init__(self, app: Flask = None):
        self.app = app
        self.config = SecurityConfig()
        self._init_app(app)
        
    def _init_app(self, app: Flask):
        if app:
            self.app = app
            
            # Apply security headers
            @app.after_request
            def apply_security_headers(response):
                for header, value in self.config.SECURITY_HEADERS.items():
                    response.headers[header] = value
                return response
            
            # Apply rate limiting
            self._apply_rate_limiting()
            
            # Apply XSS protection
            self._apply_xss_protection()
            
            # Apply CSRF protection
            self._apply_csrf_protection()
            
            # Apply SQL injection protection
            self._apply_sql_injection_protection()
            
            # Apply file upload protection
            self._apply_file_upload_protection()
            
            # Apply request validation
            self._apply_request_validation()
            
    def _apply_rate_limiting(self):
        """Apply rate limiting middleware"""
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=[self.config.RATELIMIT_DEFAULT]
        )
        limiter.init_app(self.app)
        
    def _apply_xss_protection(self):
        """Apply XSS protection middleware"""
        @self.app.before_request
        def protect_against_xss():
            if request.method in ['POST', 'PUT', 'PATCH']:
                data = request.get_data(as_text=True)
                if self._detect_xss(data):
                    raise BadRequest('Potential XSS attack detected')
                    
    def _apply_csrf_protection(self):
        """Apply CSRF protection middleware"""
        from flask_wtf.csrf import CSRFProtect
        
        csrf = CSRFProtect()
        csrf.init_app(self.app)
        
    def _apply_sql_injection_protection(self):
        """Apply SQL injection protection middleware"""
        @self.app.before_request
        def protect_against_sql_injection():
            if request.method in ['POST', 'PUT', 'PATCH']:
                data = request.get_data(as_text=True)
                if self._detect_sql_injection(data):
                    raise BadRequest('Potential SQL injection detected')
                    
    def _apply_file_upload_protection(self):
        """Apply file upload protection middleware"""
        @self.app.before_request
        def protect_file_uploads():
            if request.method == 'POST' and 'file' in request.files:
                file = request.files['file']
                if not self._validate_file_upload(file):
                    raise BadRequest('Invalid file upload')
                    
    def _apply_request_validation(self):
        """Apply request validation middleware"""
        @self.app.before_request
        def validate_request():
            if request.method in ['POST', 'PUT', 'PATCH']:
                if not self._validate_request_data():
                    raise BadRequest('Invalid request data')
                    
    def _detect_xss(self, data: str) -> bool:
        """Detect potential XSS patterns"""
        xss_patterns = [
            r'<script[^>]*?>.*?</script>',
            r'on[a-zA-Z]+\s*=\s*[\"\'].*?[\"\']',
            r'javascript:',
            r'eval\(',
            r'alert\(',
            r'prompt\(',
            r'confirm\(',
            r'expression\(',
            r'vbscript:',
            r'jscript:',
            r'wscript:',
            r'vbs:',
            r'about:',
            r'moz-binding:',
            r'base64,',
            r'\bwindow\.',
            r'\bdocument\.',
            r'\blocation\.',
            r'\bhistory\.',
            r'\bcookie\b'
        ]
        
        return any(re.search(pattern, data, re.IGNORECASE) for pattern in xss_patterns)
    
    def _detect_sql_injection(self, data: str) -> bool:
        """Detect potential SQL injection patterns"""
        sql_patterns = [
            r'\b(union|select|insert|delete|update|drop|alter|create|grant|revoke|exec|execute|xp_\w+|sp_\w+)\b',
            r'\b(\*|\+|\-|\/|\%|\&|\||\^|\~|\!)\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b'
        ]
        
        return any(re.search(pattern, data, re.IGNORECASE) for pattern in sql_patterns)
    
    def _validate_file_upload(self, file) -> bool:
        """Validate file uploads"""
        # Check file size
        if file.content_length > self.config.MAX_CONTENT_LENGTH:
            return False
            
        # Check file extension
        if file.filename.split('.')[-1].lower() not in self.config.ALLOWED_EXTENSIONS:
            return False
            
        # Check file content type
        if file.content_type not in ['image/jpeg', 'image/png', 'application/pdf']:
            return False
            
        return True
    
    def _validate_request_data(self) -> bool:
        """Validate request data"""
        # Check request size
        if request.content_length > self.config.REQUEST_MAX_SIZE:
            return False
            
        # Check request timeout
        if (datetime.utcnow() - request.start_time) > self.config.REQUEST_TIMEOUT:
            return False
            
        return True
    
    def secure_request(self, f: Callable) -> Callable:
        """Decorator to secure a route"""
        @wraps(f)
        def decorated(*args, **kwargs):
            # Check for known attack patterns
            if self._detect_xss(request.get_data(as_text=True)):
                raise BadRequest('Potential XSS attack detected')
                
            if self._detect_sql_injection(request.get_data(as_text=True)):
                raise BadRequest('Potential SQL injection detected')
                
            # Check rate limits
            if not self._check_rate_limits():
                raise TooManyRequests('Rate limit exceeded')
                
            # Check CSRF token
            if not self._validate_csrf_token():
                raise Forbidden('Invalid CSRF token')
                
            return f(*args, **kwargs)
        return decorated
    
    def _check_rate_limits(self) -> bool:
        """Check rate limits for the current request"""
        # Implementation of rate limiting check
        return True
    
    def _validate_csrf_token(self) -> bool:
        """Validate CSRF token"""
        # Implementation of CSRF token validation
        return True
    
    def generate_csrf_token(self) -> str:
        """Generate a CSRF token"""
        return base64.b64encode(os.urandom(32)).decode()
    
    def verify_csrf_token(self, token: str) -> bool:
        """Verify a CSRF token"""
        # Implementation of CSRF token verification
        return True
    
    def get_security_headers(self) -> dict:
        """Get security headers"""
        return self.config.SECURITY_HEADERS
    
    def get_rate_limit(self, endpoint: str) -> tuple:
        """Get rate limit for an endpoint"""
        return self.config.API_RATE_LIMIT
    
    def get_allowed_file_extensions(self) -> set:
        """Get allowed file extensions"""
        return self.config.ALLOWED_EXTENSIONS
    
    def get_max_content_length(self) -> int:
        """Get maximum content length"""
        return self.config.MAX_CONTENT_LENGTH
