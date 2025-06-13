"""Production configuration with security best practices."""

import os
from datetime import timedelta


class ProductionConfig:
    """Production configuration class."""
    
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    DEBUG = False
    TESTING = False
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///nvcfund_prod.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20,
        'max_overflow': 0
    }
    
    # Security configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    RATELIMIT_DEFAULT = "1000 per hour"
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # JWT configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Blockchain configuration
    ETHEREUM_NODE_URL = os.environ.get('ETHEREUM_NODE_URL') or 'https://mainnet.infura.io/v3/your-project-id'
    ETHEREUM_PRIVATE_KEY = os.environ.get('ETHEREUM_PRIVATE_KEY')
    CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS')
    
    # Payment gateway configuration
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
    PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID')
    PAYPAL_CLIENT_SECRET = os.environ.get('PAYPAL_CLIENT_SECRET')
    PAYPAL_MODE = os.environ.get('PAYPAL_MODE', 'live')
    
    # File upload configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or '/var/uploads/nvcfund'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE') or '/var/log/nvcfund/app.log'
    
    # Cache configuration
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'redis')
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')
    CACHE_DEFAULT_TIMEOUT = 300
    
    # API configuration
    API_RATE_LIMIT = "100 per minute"
    API_PAGINATION_DEFAULT = 20
    API_PAGINATION_MAX = 100
    
    # Treasury configuration
    TREASURY_DAILY_LIMIT = float(os.environ.get('TREASURY_DAILY_LIMIT', '10000000'))
    TREASURY_APPROVAL_THRESHOLD = float(os.environ.get('TREASURY_APPROVAL_THRESHOLD', '1000000'))
    
    # Stablecoin configuration
    NVCT_MINT_LIMIT = float(os.environ.get('NVCT_MINT_LIMIT', '100000000'))
    NVCT_BURN_LIMIT = float(os.environ.get('NVCT_BURN_LIMIT', '100000000'))
    
    # SWIFT configuration
    SWIFT_BIC_CODE = os.environ.get('SWIFT_BIC_CODE')
    SWIFT_INSTITUTION_NAME = os.environ.get('SWIFT_INSTITUTION_NAME', 'NVC Fund Bank')
    
    # Monitoring and alerting
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    DATADOG_API_KEY = os.environ.get('DATADOG_API_KEY')
    
    # Feature flags
    ENABLE_BLOCKCHAIN_INTEGRATION = os.environ.get('ENABLE_BLOCKCHAIN_INTEGRATION', 'true').lower() == 'true'
    ENABLE_PAYMENT_PROCESSING = os.environ.get('ENABLE_PAYMENT_PROCESSING', 'true').lower() == 'true'
    ENABLE_TREASURY_MANAGEMENT = os.environ.get('ENABLE_TREASURY_MANAGEMENT', 'true').lower() == 'true'
    ENABLE_STABLECOIN_OPERATIONS = os.environ.get('ENABLE_STABLECOIN_OPERATIONS', 'true').lower() == 'true'
    
    # Security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net;"
    }
    
    @staticmethod
    def init_app(app):
        """Initialize application with production configuration."""
        # Set up logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug:
            # File logging
            if not os.path.exists(os.path.dirname(ProductionConfig.LOG_FILE)):
                os.makedirs(os.path.dirname(ProductionConfig.LOG_FILE))
            
            file_handler = RotatingFileHandler(
                ProductionConfig.LOG_FILE,
                maxBytes=10240000,  # 10MB
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(getattr(logging, ProductionConfig.LOG_LEVEL))
            app.logger.addHandler(file_handler)
            
            app.logger.setLevel(getattr(logging, ProductionConfig.LOG_LEVEL))
            app.logger.info('NVC Fund Bank application startup')
        
        # Set up Sentry for error tracking
        if ProductionConfig.SENTRY_DSN:
            try:
                import sentry_sdk
                from sentry_sdk.integrations.flask import FlaskIntegration
                from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
                
                sentry_sdk.init(
                    dsn=ProductionConfig.SENTRY_DSN,
                    integrations=[
                        FlaskIntegration(),
                        SqlalchemyIntegration()
                    ],
                    traces_sample_rate=0.1
                )
            except ImportError:
                app.logger.warning('Sentry SDK not installed, error tracking disabled')
        
        # Set security headers
        @app.after_request
        def set_security_headers(response):
            for header, value in ProductionConfig.SECURITY_HEADERS.items():
                response.headers[header] = value
            return response