import os
from datetime import timedelta
from dotenv import load_dotenv
import secrets

load_dotenv()

class Config:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Application settings
        self.APP_NAME = os.getenv('APP_NAME', 'nvcfund-web4')
        self.DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
        self.SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
        
        # Database settings
        self.SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///nvcfund.db')
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        
        # Security settings
        self.JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
        
        # API keys
        self.PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
        self.PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET')
        self.FLUTTERWAVE_PUBLIC_KEY = os.getenv('FLUTTERWAVE_PUBLIC_KEY')
        self.FLUTTERWAVE_SECRET_KEY = os.getenv('FLUTTERWAVE_SECRET_KEY')
        self.SWIFT_API_KEY = os.getenv('SWIFT_API_KEY')
        
        # Email settings
        self.SMTP_SERVER = os.getenv('SMTP_SERVER')
        self.SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
        self.SMTP_USER = os.getenv('SMTP_USER')
        self.SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
        
        # SMS settings
        self.TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
        self.TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
        self.TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
        
        # Security settings
        self.PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '12'))
        self.PASSWORD_MAX_LENGTH = int(os.getenv('PASSWORD_MAX_LENGTH', '64'))
        self.PASSWORD_MIN_SPECIAL_CHARS = int(os.getenv('PASSWORD_MIN_SPECIAL_CHARS', '2'))
        self.PASSWORD_MIN_NUMBERS = int(os.getenv('PASSWORD_MIN_NUMBERS', '2'))
        self.PASSWORD_MIN_UPPERCASE = int(os.getenv('PASSWORD_MIN_UPPERCASE', '2'))
        self.PASSWORD_MIN_LOWERCASE = int(os.getenv('PASSWORD_MIN_LOWERCASE', '2'))
        
        # Rate limiting
        self.RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))  # seconds
        self.RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
        
        # Feature flags
        self.FEATURE_FLAGS = {
            'new_ui': os.getenv('FEATURE_NEW_UI', 'False').lower() == 'true',
            'dark_mode': os.getenv('FEATURE_DARK_MODE', 'False').lower() == 'true',
            'notifications': os.getenv('FEATURE_NOTIFICATIONS', 'False').lower() == 'true'
        }

        # Logging settings
        self.LOGGING = {
            'ENABLED': os.getenv('LOGGING_ENABLED', 'True').lower() == 'true',
            'STORAGE_OPTIONS': os.getenv('LOGGING_STORAGE_OPTIONS', 's3,database,third_party').split(','),
            'ROTATION': {
                'ENABLED': os.getenv('LOG_ROTATION_ENABLED', 'True').lower() == 'true',
                'INTERVAL': os.getenv('LOG_ROTATION_INTERVAL', 'daily'),
                'RETENTION_DAYS': {
                    'S3': int(os.getenv('S3_LOG_RETENTION_DAYS', '30')),
                    'DATABASE': int(os.getenv('DATABASE_LOG_RETENTION_DAYS', '90')),
                    'LOCAL': int(os.getenv('LOCAL_LOG_RETENTION_DAYS', '7'))
                }
            },
            'S3': {
                'ENABLED': os.getenv('S3_LOGGING_ENABLED', 'True').lower() == 'true',
                'BUCKET': os.getenv('S3_LOG_BUCKET'),
                'PREFIX': os.getenv('S3_LOG_PREFIX', 'logs/'),
                'REGION': os.getenv('AWS_REGION', 'us-east-1'),
                'ACCESS_KEY': os.getenv('AWS_ACCESS_KEY'),
                'SECRET_KEY': os.getenv('AWS_SECRET_KEY')
            },
            'DATABASE': {
                'ENABLED': os.getenv('DATABASE_LOGGING_ENABLED', 'True').lower() == 'true',
                'TABLE': os.getenv('DATABASE_LOG_TABLE', 'security_logs'),
                'BATCH_SIZE': int(os.getenv('DATABASE_LOG_BATCH_SIZE', '100'))
            },
            'THIRD_PARTY': {
                'SPLUNK': {
                    'ENABLED': os.getenv('SPLUNK_ENABLED', 'False').lower() == 'true',
                    'URL': os.getenv('SPLUNK_URL'),
                    'TOKEN': os.getenv('SPLUNK_TOKEN')
                },
                'ELK': {
                    'ENABLED': os.getenv('ELK_ENABLED', 'False').lower() == 'true',
                    'URL': os.getenv('ELK_URL'),
                    'INDEX': os.getenv('ELK_INDEX', 'security-logs')
                },
                'DATADOG': {
                    'ENABLED': os.getenv('DATADOG_ENABLED', 'False').lower() == 'true',
                    'API_KEY': os.getenv('DATADOG_API_KEY'),
                    'SERVICE': os.getenv('DATADOG_SERVICE', 'nvcfund')
                }
            }
        }

        # Blockchain
        self.BLOCKCHAIN_CURRENCIES = ['BTC', 'ETH', 'USDT']
        self.MAX_VOLUME_THRESHOLD = 1000000
        self.MAX_FREQUENCY_THRESHOLD = 100
        
        # Conversion Limits
        self.CONVERSION_LIMITS = {
            'BTC': {'max_amount': 100.0},
            'ETH': {'max_amount': 1000.0},
            'USDT': {'max_amount': 100000.0},
            'USD': {'max_amount': 1000000.0},
            'EUR': {'max_amount': 1000000.0}
        }

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///nvcfund-dev.db')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_URL', 'sqlite:///nvcfund-test.db')
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
