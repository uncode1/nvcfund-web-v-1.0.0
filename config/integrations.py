from typing import Dict, Any
from decouple import config

INTEGRATIONS_CONFIG = {
    'stripe': {
        'api_key': config('STRIPE_API_KEY', default=''),
        'webhook_secret': config('STRIPE_WEBHOOK_SECRET', default=''),
        'enabled': config('STRIPE_ENABLED', default=False, cast=bool)
    },
    'paypal': {
        'client_id': config('PAYPAL_CLIENT_ID', default=''),
        'client_secret': config('PAYPAL_CLIENT_SECRET', default=''),
        'mode': config('PAYPAL_MODE', default='sandbox'),
        'enabled': config('PAYPAL_ENABLED', default=False, cast=bool)
    },
    'braintree': {
        'merchant_id': config('BRAINTREE_MERCHANT_ID', default=''),
        'public_key': config('BRAINTREE_PUBLIC_KEY', default=''),
        'private_key': config('BRAINTREE_PRIVATE_KEY', default=''),
        'enabled': config('BRAINTREE_ENABLED', default=False, cast=bool)
    },
    'sentry': {
        'dsn': config('SENTRY_DSN', default=''),
        'environment': config('SENTRY_ENVIRONMENT', default='development'),
        'enabled': config('SENTRY_ENABLED', default=False, cast=bool)
    },
    'newrelic': {
        'license_key': config('NEWRELIC_LICENSE_KEY', default=''),
        'app_name': config('NEWRELIC_APP_NAME', default=''),
        'enabled': config('NEWRELIC_ENABLED', default=False, cast=bool)
    },
    'redis': {
        'host': config('REDIS_HOST', default='localhost'),
        'port': config('REDIS_PORT', default=6379, cast=int),
        'password': config('REDIS_PASSWORD', default=''),
        'enabled': config('REDIS_ENABLED', default=False, cast=bool)
    },
    'elasticsearch': {
        'hosts': config('ELASTICSEARCH_HOSTS', default='localhost:9200'),
        'username': config('ELASTICSEARCH_USERNAME', default=''),
        'password': config('ELASTICSEARCH_PASSWORD', default=''),
        'enabled': config('ELASTICSEARCH_ENABLED', default=False, cast=bool)
    },
    'rabbitmq': {
        'host': config('RABBITMQ_HOST', default='localhost'),
        'port': config('RABBITMQ_PORT', default=5672, cast=int),
        'username': config('RABBITMQ_USERNAME', default='guest'),
        'password': config('RABBITMQ_PASSWORD', default='guest'),
        'enabled': config('RABBITMQ_ENABLED', default=False, cast=bool)
    }
}

# Integration-specific settings
INTEGRATION_SETTINGS = {
    'sync_interval': {
        'default': 300,  # 5 minutes
        'stripe': 60,    # 1 minute
        'paypal': 300,   # 5 minutes
        'braintree': 300 # 5 minutes
    },
    'retry_attempts': {
        'default': 3,
        'stripe': 5,
        'paypal': 3,
        'braintree': 3
    },
    'retry_delay': {
        'default': 60,   # 1 minute
        'stripe': 30,    # 30 seconds
        'paypal': 60,    # 1 minute
        'braintree': 60  # 1 minute
    }
}

# Webhook settings
WEBHOOK_SETTINGS = {
    'timeout': 10,      # 10 seconds
    'retry_limit': 3,
    'retry_delay': 60,  # 1 minute
    'max_queue_size': 1000
}

# Rate limiting settings
RATE_LIMITING = {
    'enabled': True,
    'window_size': 60,  # 1 minute
    'max_requests': 1000,
    'per_integration': {
        'stripe': 1000,
        'paypal': 500,
        'braintree': 500
    }
}

# Security settings
SECURITY = {
    'api_key_rotation': {
        'enabled': True,
        'interval': 90,  # 90 days
        'integrations': ['stripe', 'paypal', 'braintree']
    },
    'webhook_validation': True,
    'ip_whitelist': {
        'enabled': True,
        'integrations': {
            'stripe': [],
            'paypal': [],
            'braintree': []
        }
    }
}

# Monitoring settings
MONITORING = {
    'enabled': True,
    'check_interval': 60,  # 1 minute
    'alert_thresholds': {
        'error_rate': 0.05,  # 5%
        'latency': 1000,     # 1 second
        'queue_size': 1000
    }
}
