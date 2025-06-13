"""Development configuration for local development."""

import os
from datetime import timedelta


class DevelopmentConfig:
    """Development configuration class."""
    
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-not-for-production'
    DEBUG = True
    TESTING = False
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///nvcfund_dev.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True  # Log SQL queries in development
    
    # Security configuration (relaxed for development)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # CSRF Protection (can be disabled for API testing)
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'
    WTF_CSRF_TIME_LIMIT = None  # No time limit in development
    
    # Rate limiting (more permissive in development)
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = "10000 per hour"
    
    # Email configuration (use console backend for development)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'localhost'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 1025)  # MailHog default port
    MAIL_USE_TLS = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@nvcfund.dev'
    
    # JWT configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Longer for development
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Blockchain configuration (testnet)
    ETHEREUM_NODE_URL = os.environ.get('ETHEREUM_NODE_URL') or 'https://sepolia.infura.io/v3/your-project-id'
    ETHEREUM_PRIVATE_KEY = os.environ.get('ETHEREUM_PRIVATE_KEY')
    CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS')
    
    # Payment gateway configuration (sandbox/test mode)
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_TEST_PUBLISHABLE_KEY')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_TEST_SECRET_KEY')
    PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_SANDBOX_CLIENT_ID')
    PAYPAL_CLIENT_SECRET = os.environ.get('PAYPAL_SANDBOX_CLIENT_SECRET')
    PAYPAL_MODE = 'sandbox'
    
    # File upload configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or './uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
    
    # Cache configuration
    CACHE_TYPE = 'simple'  # Simple in-memory cache for development
    CACHE_DEFAULT_TIMEOUT = 300
    
    # API configuration
    API_RATE_LIMIT = "1000 per minute"  # More permissive for development
    API_PAGINATION_DEFAULT = 20
    API_PAGINATION_MAX = 100
    
    # Treasury configuration (lower limits for testing)
    TREASURY_DAILY_LIMIT = float(os.environ.get('TREASURY_DAILY_LIMIT', '100000'))
    TREASURY_APPROVAL_THRESHOLD = float(os.environ.get('TREASURY_APPROVAL_THRESHOLD', '10000'))
    
    # Stablecoin configuration
    NVCT_MINT_LIMIT = float(os.environ.get('NVCT_MINT_LIMIT', '1000000'))
    NVCT_BURN_LIMIT = float(os.environ.get('NVCT_BURN_LIMIT', '1000000'))
    
    # SWIFT configuration
    SWIFT_BIC_CODE = os.environ.get('SWIFT_BIC_CODE') or 'NVCFTEST'
    SWIFT_INSTITUTION_NAME = os.environ.get('SWIFT_INSTITUTION_NAME', 'NVC Fund Bank (Test)')
    
    # Feature flags (all enabled in development)
    ENABLE_BLOCKCHAIN_INTEGRATION = True
    ENABLE_PAYMENT_PROCESSING = True
    ENABLE_TREASURY_MANAGEMENT = True
    ENABLE_STABLECOIN_OPERATIONS = True
    
    # Development tools
    FLASK_ENV = 'development'
    TEMPLATES_AUTO_RELOAD = True
    SEND_FILE_MAX_AGE_DEFAULT = 0  # Disable caching for development
    
    @staticmethod
    def init_app(app):
        """Initialize application with development configuration."""
        import logging
        
        # Set up console logging for development
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        console_handler.setLevel(logging.DEBUG)
        
        app.logger.addHandler(console_handler)
        app.logger.setLevel(logging.DEBUG)
        app.logger.info('NVC Fund Bank application startup (Development Mode)')
        
        # Create upload directory if it doesn't exist
        upload_dir = app.config.get('UPLOAD_FOLDER', './uploads')
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
            app.logger.info(f'Created upload directory: {upload_dir}')
        
        # Development-specific middleware
        @app.after_request
        def after_request(response):
            # Add CORS headers for development
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key'
            return response