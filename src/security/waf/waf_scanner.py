from typing import Dict, Any, Optional
import re
from enum import Enum
from security.logging.security_logger import SecurityLogger

class WAFViolationType(Enum):
    XSS = 'xss'
    SQL_INJECTION = 'sql_injection'
    RCE = 'rce'
    PATH_TRAVERSAL = 'path_traversal'
    CSRF = 'csrf'
    DDoS = 'ddos'

class WAFScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self.patterns = self._load_patterns()
        self.whitelist = self._load_whitelist()
        self.blacklist = self._load_blacklist()
        
    def _load_patterns(self) -> Dict[str, Any]:
        """Load WAF patterns"""
        return {
            WAFViolationType.XSS: [
                r'<script.*?>.*?</script>',
                r'on[a-zA-Z]+=".*?"',
                r'javascript:.*?'
            ],
            WAFViolationType.SQL_INJECTION: [
                r'\b(SELECT|INSERT|UPDATE|DELETE)\b',
                r'\b(UNION|OR|AND)\b',
                r'\b(SELECT\s+.*?\s+FROM)\b',
                r'\b(UPDATE\s+.*?\s+SET)\b',
                r'\b(DELETE\s+FROM)\b'
            ],
            WAFViolationType.RCE: [
                r'\b(system|exec|shell_exec|passthru)\b',
                r'\b(eval|assert|include|require)\b',
                r'\b(phpinfo|phpversion)\b'
            ],
            WAFViolationType.PATH_TRAVERSAL: [
                r'\.{2}/',
                r'/\.\./',
                r'\.{2}\\',
                r'\\\.\.\\'
            ],
            WAFViolationType.CSRF: [
                r'\b(token|csrf|auth)\b',
                r'\b(session|cookie)\b',
                r'\b(header|referer)\b'
            ],
            WAFViolationType.DDoS: [
                r'\b(flood|attack|stress)\b',
                r'\b(ping|syn|udp)\b',
                r'\b(ddos|dos|bot)\b'
            ]
        }
    
    def _load_whitelist(self) -> List[str]:
        """Load whitelist of allowed patterns"""
        return self.config.get('WAF_WHITELIST', [])
    
    def _load_blacklist(self) -> List[str]:
        """Load blacklist of blocked patterns"""
        return self.config.get('WAF_BLACKLIST', [])
    
    def scan_request(self, request: Any) -> bool:
        """Scan request for WAF violations"""
        try:
            # Check request method
            if not self._validate_method(request.method):
                return False
                
            # Check headers
            if not self._validate_headers(request.headers):
                return False
                
            # Check URL
            if not self._validate_url(request.url):
                return False
                
            # Check data
            if not self._validate_data(request.data):
                return False
                
            # Check IP address
            if not self._validate_ip(request.remote_addr):
                return False
                
            return True
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='waf_scan_failed',
                error=str(e)
            )
            return False
    
    def _validate_method(self, method: str) -> bool:
        """Validate request method"""
        allowed_methods = self.config.get('ALLOWED_METHODS', ['GET', 'POST', 'PUT', 'DELETE'])
        return method in allowed_methods
    
    def _validate_headers(self, headers: Dict[str, str]) -> bool:
        """Validate request headers"""
        for header, value in headers.items():
            if not self._validate_header_value(header, value):
                return False
        return True
    
    def _validate_header_value(self, header: str, value: str) -> bool:
        """Validate header value"""
        # Check for injection patterns
        if any(re.search(pattern, value, re.IGNORECASE) 
               for pattern in self.patterns[WAFViolationType.XSS]):
            return False
            
        # Check for CSRF patterns
        if any(re.search(pattern, value, re.IGNORECASE) 
               for pattern in self.patterns[WAFViolationType.CSRF]):
            return False
            
        return True
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL"""
        # Check for path traversal
        if any(re.search(pattern, url, re.IGNORECASE) 
               for pattern in self.patterns[WAFViolationType.PATH_TRAVERSAL]):
            return False
            
        # Check for SQL injection
        if any(re.search(pattern, url, re.IGNORECASE) 
               for pattern in self.patterns[WAFViolationType.SQL_INJECTION]):
            return False
            
        return True
    
    def _validate_data(self, data: bytes) -> bool:
        """Validate request data"""
        if not data:
            return True
            
        text = data.decode('utf-8', errors='ignore')
        
        # Check for injection patterns
        if any(re.search(pattern, text, re.IGNORECASE) 
               for pattern in self.patterns[WAFViolationType.XSS]):
            return False
            
        # Check for SQL injection
        if any(re.search(pattern, text, re.IGNORECASE) 
               for pattern in self.patterns[WAFViolationType.SQL_INJECTION]):
            return False
            
        return True
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        # Check blacklist
        if ip in self.blacklist:
            return False
            
        # Check whitelist
        if self.whitelist and ip not in self.whitelist:
            return False
            
        return True
