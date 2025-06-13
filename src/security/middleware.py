from flask import Flask, request, Response
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests
from security.web import WebSecurity
from security.waf import WAF
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    def __init__(self, app: Flask = None):
        self.app = app
        self.web_security = WebSecurity()
        self.waf = WAF()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        self.app = app
        
        @app.before_request
        def security_check():
            # Get request data
            request_data = {
                'ip': request.remote_addr,
                'method': request.method,
                'path': request.path,
                'headers': dict(request.headers),
                'data': request.get_data(as_text=True)
            }
            
            # Check WAF
            if not self.waf.scan_request(request_data):
                logger.warning(f"WAF blocked request: {request.path}")
                raise Forbidden('Access denied by security system')
                
            # Check rate limits
            if not self._check_rate_limits(request_data):
                raise TooManyRequests('Rate limit exceeded')
                
            # Check CSRF
            if not self._validate_csrf():
                raise Forbidden('Invalid CSRF token')
                
            # Check XSS
            if self._detect_xss(request_data):
                raise BadRequest('Potential XSS attack detected')
                
            # Check SQL injection
            if self._detect_sql_injection(request_data):
                raise BadRequest('Potential SQL injection detected')
                
        @app.after_request
        def apply_security_headers(response):
            # Add security headers
            for header, value in self.web_security.get_security_headers().items():
                response.headers[header] = value
            
            # Add rate limit headers
            self._add_rate_limit_headers(response)
            
            return response
    
    def _check_rate_limits(self, request_data: dict) -> bool:
        """Check rate limits for the request"""
        # Check IP rate limit
        if not self._check_ip_rate_limit(request_data['ip']):
            return False
            
        # Check endpoint rate limit
        if not self._check_endpoint_rate_limit(request_data['path']):
            return False
            
        return True
    
    def _check_ip_rate_limit(self, ip: str) -> bool:
        """Check rate limit for IP"""
        # Implementation of IP rate limiting
        return True
    
    def _check_endpoint_rate_limit(self, endpoint: str) -> bool:
        """Check rate limit for endpoint"""
        # Implementation of endpoint rate limiting
        return True
    
    def _validate_csrf(self) -> bool:
        """Validate CSRF token"""
        # Implementation of CSRF token validation
        return True
    
    def _detect_xss(self, request_data: dict) -> bool:
        """Detect XSS in request data"""
        return self.waf._detect_attack(request_data, self.waf.attack_patterns['xss'])
    
    def _detect_sql_injection(self, request_data: dict) -> bool:
        """Detect SQL injection in request data"""
        return self.waf._detect_attack(request_data, self.waf.attack_patterns['sql'])
    
    def _add_rate_limit_headers(self, response: Response):
        """Add rate limit headers to response"""
        # Implementation of rate limit headers
        pass
    
    def secure_route(self, f: Callable) -> Callable:
        """Decorator to secure a route"""
        @wraps(f)
        def decorated(*args, **kwargs):
            # Check for known attack patterns
            if self._detect_xss(request.get_data(as_text=True)):
                raise BadRequest('Potential XSS attack detected')
                
            if self._detect_sql_injection(request.get_data(as_text=True)):
                raise BadRequest('Potential SQL injection detected')
                
            # Check rate limits
            if not self._check_rate_limits({
                'ip': request.remote_addr,
                'path': request.path
            }):
                raise TooManyRequests('Rate limit exceeded')
                
            return f(*args, **kwargs)
        return decorated
    
    def require_csrf_token(self, f: Callable) -> Callable:
        """Decorator to require CSRF token"""
        @wraps(f)
        def decorated(*args, **kwargs):
            if not self._validate_csrf():
                raise Forbidden('Invalid CSRF token')
            return f(*args, **kwargs)
        return decorated
    
    def require_ip_whitelist(self, whitelist: list):
        """Decorator to require IP whitelist"""
        def decorator(f: Callable):
            @wraps(f)
            def decorated(*args, **kwargs):
                if request.remote_addr not in whitelist:
                    raise Forbidden('IP not allowed')
                return f(*args, **kwargs)
            return decorated
        return decorator
    
    def require_rate_limit(self, limit: int, window: timedelta):
        """Decorator to apply rate limiting"""
        def decorator(f: Callable):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not self._check_rate_limits({
                    'ip': request.remote_addr,
                    'path': request.path
                }):
                    raise TooManyRequests('Rate limit exceeded')
                return f(*args, **kwargs)
            return decorated
        return decorator
