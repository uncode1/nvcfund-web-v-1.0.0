import os
from datetime import timedelta

class SecurityConfig:
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', os.urandom(32).hex())
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Session Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_REFRESH_EACH_REQUEST = True
    
    # Rate Limiting
    RATELIMIT_STORAGE_URI = 'memory://'  # Can be changed to Redis in production
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = '1000 per day;100 per hour'
    
    # Password Requirements
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_MAX_LENGTH = 64
    PASSWORD_REQUIREMENTS = {
        'uppercase': True,
        'lowercase': True,
        'digits': True,
        'special_chars': True,
        'min_length': PASSWORD_MIN_LENGTH
    }
    
    # MFA Configuration
    MFA_REQUIRED = True
    MFA_TIMEOUT = timedelta(minutes=15)
    MFA_RETRY_LIMIT = 3
    
    # Audit Logging
    AUDIT_LOG_MAX_AGE = timedelta(days=90)
    AUDIT_LOG_BATCH_SIZE = 1000
    
    # CORS Configuration
    CORS_ORIGINS = ['https://*.nvcfund.com']
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_HEADERS = ['Content-Type', 'Authorization']
    
    # SSL/TLS Configuration
    SSL_CERTIFICATE = os.getenv('SSL_CERTIFICATE')
    SSL_PRIVATE_KEY = os.getenv('SSL_PRIVATE_KEY')
    SSL_PROTOCOL = 'TLSv1.2'
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-src 'none';",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Error Reporting
    ERROR_REPORTING_ENABLED = True
    ERROR_REPORTING_SERVICE = 'sentry'  # Can be changed to other services
    ERROR_REPORTING_DSN = os.getenv('ERROR_REPORTING_DSN')
    
    # File Upload Security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    
    # Database Security
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_SIZE = 10
    SQLALCHEMY_POOL_TIMEOUT = 30
    SQLALCHEMY_MAX_OVERFLOW = 20
    
    # API Rate Limiting
    API_RATE_LIMIT = '1000 per day;100 per hour'
    API_RATE_LIMIT_WINDOW = timedelta(hours=1)
    API_RATE_LIMIT_EXEMPT_ROUTES = ['/api/v1/health', '/api/v1/docs']
    
    # IP Whitelisting
    IP_WHITELIST_ENABLED = True
    IP_WHITELIST = []  # To be configured in production
    
    # Request Validation
    REQUEST_MAX_SIZE = 100 * 1024 * 1024  # 100MB
    REQUEST_TIMEOUT = timedelta(seconds=30)
    
    # Security Audit
    SECURITY_AUDIT_ENABLED = True
    SECURITY_AUDIT_LOG_LEVEL = 'INFO'
    SECURITY_AUDIT_RETENTION = timedelta(days=30)
