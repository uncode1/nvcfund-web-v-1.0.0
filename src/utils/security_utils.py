"""Security utilities for input validation and access control."""

import re
import html
import logging
from decimal import Decimal, InvalidOperation
from functools import wraps
from typing import Any, Union

from flask import abort, current_app
from flask_login import current_user


logger = logging.getLogger(__name__)


def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks.
    
    Args:
        input_string: Raw input string
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not isinstance(input_string, str):
        return ""
    
    # Truncate to max length
    sanitized = input_string[:max_length]
    
    # HTML escape to prevent XSS
    sanitized = html.escape(sanitized)
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()
    
    return sanitized


def validate_amount(amount: Union[str, int, float, Decimal]) -> Decimal:
    """
    Validate and convert amount to Decimal for precise financial calculations.
    
    Args:
        amount: Amount to validate
        
    Returns:
        Validated Decimal amount
        
    Raises:
        ValueError: If amount is invalid
    """
    try:
        # Convert to Decimal for precision
        decimal_amount = Decimal(str(amount))
        
        # Check for reasonable bounds
        if decimal_amount < 0:
            raise ValueError("Amount cannot be negative")
        
        if decimal_amount > Decimal('999999999.99'):
            raise ValueError("Amount exceeds maximum limit")
        
        # Check decimal places (max 2 for currency)
        if decimal_amount.as_tuple().exponent < -2:
            raise ValueError("Amount cannot have more than 2 decimal places")
        
        return decimal_amount
        
    except (InvalidOperation, ValueError, TypeError) as e:
        raise ValueError(f"Invalid amount: {str(e)}")


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(email, str):
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Check length constraints
    if len(email) > 254 or len(email) < 5:
        return False
    
    return bool(re.match(pattern, email))


def validate_phone(phone: str) -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(phone, str):
        return False
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\+\.]', '', phone)
    
    # Check if it's all digits and reasonable length
    if not cleaned.isdigit():
        return False
    
    if len(cleaned) < 7 or len(cleaned) > 15:
        return False
    
    return True


def validate_account_number(account_number: str) -> bool:
    """
    Validate account number format.
    
    Args:
        account_number: Account number to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(account_number, str):
        return False
    
    # Remove spaces and hyphens
    cleaned = re.sub(r'[\s\-]', '', account_number)
    
    # Check length and format (alphanumeric)
    if len(cleaned) < 5 or len(cleaned) > 64:
        return False
    
    if not re.match(r'^[a-zA-Z0-9]+$', cleaned):
        return False
    
    return True


def admin_required(f):
    """
    Decorator to require admin access.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        
        # Check if user has admin role
        if not (current_user.is_admin or 
                (hasattr(current_user, 'role') and 
                 current_user.role and 
                 current_user.role.value == 'admin')):
            logger.warning(f"Unauthorized admin access attempt by user {current_user.id}")
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function


def api_key_required(f):
    """
    Decorator to require valid API key.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request
        from ..models import User
        
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            abort(401, description="API key required")
        
        # Validate API key
        user = User.query.filter_by(api_key=api_key, is_active=True).first()
        
        if not user:
            logger.warning(f"Invalid API key used: {api_key[:8]}...")
            abort(401, description="Invalid API key")
        
        # Set current user context for API requests
        request.api_user = user
        
        return f(*args, **kwargs)
    return decorated_function


def rate_limit_key(identifier: str) -> str:
    """
    Generate rate limiting key.
    
    Args:
        identifier: Unique identifier (IP, user ID, etc.)
        
    Returns:
        Rate limit key
    """
    return f"rate_limit:{sanitize_input(identifier)}"


def log_security_event(event_type: str, details: dict, user_id: int = None):
    """
    Log security-related events.
    
    Args:
        event_type: Type of security event
        details: Event details
        user_id: Optional user ID
    """
    try:
        from flask import request
        
        log_data = {
            'event_type': event_type,
            'details': details,
            'user_id': user_id or (current_user.id if current_user.is_authenticated else None),
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'timestamp': logger.handlers[0].formatter.formatTime(logger.makeRecord(
                logger.name, logging.INFO, __file__, 0, "", (), None
            )) if logger.handlers else None
        }
        
        logger.warning(f"Security Event: {event_type} - {log_data}")
        
        # Here you could also store to database or send to external monitoring
        
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")


def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging/display.
    
    Args:
        data: Sensitive data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to leave visible
        
    Returns:
        Masked string
    """
    if not isinstance(data, str) or len(data) <= visible_chars:
        return mask_char * len(data) if data else ""
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)


def validate_currency_code(currency: str) -> bool:
    """
    Validate currency code format.
    
    Args:
        currency: Currency code to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(currency, str):
        return False
    
    # Standard 3-letter currency codes
    if len(currency) != 3:
        return False
    
    if not currency.isalpha():
        return False
    
    # List of supported currencies
    supported_currencies = {
        'USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD', 'NZD',
        'SEK', 'NOK', 'DKK', 'PLN', 'CZK', 'HUF', 'RON', 'BGN',
        'HRK', 'RUB', 'CNY', 'INR', 'KRW', 'SGD', 'HKD', 'THB',
        'MYR', 'IDR', 'PHP', 'VND', 'BRL', 'MXN', 'ARS', 'CLP',
        'COP', 'PEN', 'UYU', 'ZAR', 'EGP', 'MAD', 'TND', 'KES',
        'NGN', 'GHS', 'XOF', 'XAF', 'NVCT', 'AFD1'  # Include custom tokens
    }
    
    return currency.upper() in supported_currencies


def check_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Check password strength and return validation results.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_strong, list_of_issues)
    """
    issues = []
    
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")
    
    if len(password) > 128:
        issues.append("Password must be less than 128 characters")
    
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'\d', password):
        issues.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("Password must contain at least one special character")
    
    # Check for common weak patterns
    weak_patterns = [
        r'(.)\1{2,}',  # Repeated characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password.lower()):
            issues.append("Password contains weak patterns")
            break
    
    return len(issues) == 0, issues