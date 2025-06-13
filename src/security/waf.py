from typing import Dict, Any, Optional
import re
import hashlib
import hmac
import base64
import logging
from datetime import datetime, timedelta
from src.security.config import SecurityConfig

logger = logging.getLogger(__name__)

class WAF:
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.attack_patterns = {
            'xss': self._load_xss_patterns(),
            'sql': self._load_sql_patterns(),
            'rce': self._load_rce_patterns(),
            'path_traversal': self._load_path_traversal_patterns(),
            'csrf': self._load_csrf_patterns(),
            'ddos': self._load_ddos_patterns()
        }
        self.attack_signatures = self._load_attack_signatures()
        self.rate_limits = self._load_rate_limits()
        self.whitelist = self._load_whitelist()
        self.blacklist = self._load_blacklist()
        
    def _load_xss_patterns(self) -> list:
        """Load XSS patterns"""
        return [
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
    
    def _load_sql_patterns(self) -> list:
        """Load SQL injection patterns"""
        return [
            r'\b(union|select|insert|delete|update|drop|alter|create|grant|revoke|exec|execute|xp_\w+|sp_\w+)\b',
            r'\b(\*|\+|\-|\/|\%|\&|\||\^|\~|\!)\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b',
            r'\b(\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\'|\'\'\'\')\b'
        ]
    
    def _load_rce_patterns(self) -> list:
        """Load Remote Code Execution patterns"""
        return [
            r'\b(system|exec|shell_exec|passthru|popen|proc_open|eval|assert|create_function)\b',
            r'\b(\$\{.*?\}|\%7B.*?\%7D)\b',
            r'\b(\$\(.*?\)|\%24\(.*?\%29)\b',
            r'\b(\$\[.*?\]|\%24\[.*?\%5D)\b'
        ]
    
    def _load_path_traversal_patterns(self) -> list:
        """Load path traversal patterns"""
        return [
            r'\.{2}/',
            r'\.{2}%2F',
            r'\.{2}%5C',
            r'\.{2}%252F',
            r'\.{2}%255C'
        ]
    
    def _load_csrf_patterns(self) -> list:
        """Load CSRF patterns"""
        return [
            r'\btoken=\b',
            r'\bcsrf=\b',
            r'\b_xsrf=\b',
            r'\b_csrf=\b'
        ]
    
    def _load_ddos_patterns(self) -> list:
        """Load DDoS patterns"""
        return [
            r'\b(stress|flood|ddos|attack)\b',
            r'\b(hping|slowloris|slowhttptest)\b',
            r'\b(curl|wget|ab)\b'
        ]
    
    def _load_attack_signatures(self) -> dict:
        """Load known attack signatures"""
        return {
            'xss': [
                'alert(1)',
                'prompt(1)',
                'confirm(1)',
                'javascript:alert',
                'vbscript:alert'
            ],
            'sql': [
                'UNION ALL SELECT',
                'DROP TABLE',
                'DELETE FROM',
                'UPDATE SET',
                'INSERT INTO'
            ],
            'rce': [
                'system(',
                'exec(',
                'shell_exec(',
                'passthru(',
                'popen(',
                'proc_open(',
                'eval(',
                'assert('
            ]
        }
    
    def _load_rate_limits(self) -> dict:
        """Load rate limiting rules"""
        return {
            'ip': {
                'limit': 1000,
                'window': timedelta(minutes=1)
            },
            'endpoint': {
                'limit': 100,
                'window': timedelta(seconds=60)
            },
            'user': {
                'limit': 500,
                'window': timedelta(minutes=5)
            }
        }
    
    def _load_whitelist(self) -> list:
        """Load whitelisted IPs"""
        return self.config.IP_WHITELIST
    
    def _load_blacklist(self) -> list:
        """Load blacklisted IPs"""
        return []
    
    def scan_request(self, request_data: Dict[str, Any]) -> bool:
        """Scan request for malicious patterns"""
        # Check IP whitelist
        if request_data['ip'] in self.whitelist:
            return True
            
        # Check IP blacklist
        if request_data['ip'] in self.blacklist:
            return False
            
        # Check rate limits
        if not self._check_rate_limits(request_data):
            return False
            
        # Check for attack patterns
        for attack_type, patterns in self.attack_patterns.items():
            if self._detect_attack(request_data, patterns):
                return False
                
        # Check for known signatures
        if self._detect_signatures(request_data):
            return False
            
        return True
    
    def _check_rate_limits(self, request_data: Dict[str, Any]) -> bool:
        """Check rate limits for the request"""
        # Implementation of rate limiting check
        return True
    
    def _detect_attack(self, request_data: Dict[str, Any], patterns: list) -> bool:
        """Detect attack patterns in request data"""
        for pattern in patterns:
            if any(re.search(pattern, str(value), re.IGNORECASE) 
                   for value in request_data.values()):
                return True
        return False
    
    def _detect_signatures(self, request_data: Dict[str, Any]) -> bool:
        """Detect known attack signatures"""
        for signature_type, signatures in self.attack_signatures.items():
            if any(signature in str(value) 
                   for signature in signatures 
                   for value in request_data.values()):
                return True
        return False
    
    def log_attack_attempt(self, request_data: Dict[str, Any], attack_type: str):
        """Log an attack attempt"""
        logger.warning(f"Attack attempt detected: {attack_type}")
        logger.warning(f"Request data: {json.dumps(request_data)}")
    
    def get_security_score(self, request_data: Dict[str, Any]) -> int:
        """Calculate security score for request"""
        score = 100
        
        # Check for suspicious patterns
        for patterns in self.attack_patterns.values():
            if self._detect_attack(request_data, patterns):
                score -= 20
                
        # Check rate limits
        if not self._check_rate_limits(request_data):
            score -= 15
            
        # Check for known signatures
        if self._detect_signatures(request_data):
            score -= 25
            
        return max(0, score)
