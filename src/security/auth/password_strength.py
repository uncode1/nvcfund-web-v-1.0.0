import re
from typing import Dict, List, Optional
from security.logging.security_logger import SecurityLogger

class PasswordStrengthChecker:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self.dictionary = self._load_dictionary()
        self.common_patterns = self._load_common_patterns()
        
    def _load_dictionary(self) -> List[str]:
        """Load dictionary of common passwords"""
        # Load from file or database
        return [
            'password',
            '123456',
            'qwerty',
            'admin',
            'root',
            # Add more common passwords
        ]
    
    def _load_common_patterns(self) -> List[str]:
        """Load common weak patterns"""
        return [
            r'^[0-9]+$',  # Only numbers
            r'^[a-zA-Z]+$',  # Only letters
            r'^[!@#$%^&*()_+=-]+$',  # Only special characters
            r'^[a-z]+$',  # Only lowercase
            r'^[A-Z]+$',  # Only uppercase
            r'.*(.)\1{2,}.*',  # Repeated characters
            r'.*(.).*\1.*\1.*',  # Repeated sequence
        ]
    
    def is_strong(self, password: str) -> bool:
        """Check if password is strong"""
        try:
            # Check length
            if len(password) < 12:
                self.logger.log_event(
                    SecurityEventType.AUTHENTICATION,
                    SecurityEventSeverity.WARNING,
                    event_type='weak_password',
                    reason='too_short'
                )
                return False
                
            # Check dictionary words
            if self._contains_dictionary_word(password):
                self.logger.log_event(
                    SecurityEventType.AUTHENTICATION,
                    SecurityEventSeverity.WARNING,
                    event_type='weak_password',
                    reason='dictionary_word'
                )
                return False
                
            # Check common patterns
            if self._matches_common_pattern(password):
                self.logger.log_event(
                    SecurityEventType.AUTHENTICATION,
                    SecurityEventSeverity.WARNING,
                    event_type='weak_password',
                    reason='common_pattern'
                )
                return False
                
            # Check character requirements
            if not self._meets_character_requirements(password):
                self.logger.log_event(
                    SecurityEventType.AUTHENTICATION,
                    SecurityEventSeverity.WARNING,
                    event_type='weak_password',
                    reason='missing_requirements'
                )
                return False
                
            return True
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='password_check_failed',
                error=str(e)
            )
            return False
    
    def _contains_dictionary_word(self, password: str) -> bool:
        """Check if password contains dictionary words"""
        password_lower = password.lower()
        return any(word in password_lower for word in self.dictionary)
    
    def _matches_common_pattern(self, password: str) -> bool:
        """Check if password matches common weak patterns"""
        return any(re.match(pattern, password) for pattern in self.common_patterns)
    
    def _meets_character_requirements(self, password: str) -> bool:
        """Check if password meets character requirements"""
        # Must have at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            return False
            
        # Must have at least one lowercase letter
        if not re.search(r'[a-z]', password):
            return False
            
        # Must have at least one number
        if not re.search(r'[0-9]', password):
            return False
            
        # Must have at least one special character
        if not re.search(r'[!@#$%^&*()_+=-]', password):
            return False
            
        # Must not have consecutive identical characters
        if re.search(r'(.)\1', password):
            return False
            
        return True
    
    def get_strength_score(self, password: str) -> float:
        """Get password strength score (0.0 - 1.0)"""
        score = 0.0
        
        # Length score
        length_score = min(len(password) / 20, 1.0)
        score += length_score * 0.3
        
        # Character type score
        char_types = 0
        if re.search(r'[A-Z]', password): char_types += 1
        if re.search(r'[a-z]', password): char_types += 1
        if re.search(r'[0-9]', password): char_types += 1
        if re.search(r'[!@#$%^&*()_+=-]', password): char_types += 1
        score += (char_types / 4) * 0.3
        
        # Pattern score
        pattern_score = 1.0
        if self._matches_common_pattern(password):
            pattern_score = 0.2
        score += pattern_score * 0.2
        
        # Dictionary score
        dict_score = 1.0
        if self._contains_dictionary_word(password):
            dict_score = 0.2
        score += dict_score * 0.2
        
        return score
