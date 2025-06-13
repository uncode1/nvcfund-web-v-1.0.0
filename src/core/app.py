#!/usr/bin/env python3
"""
Main application entry point
"""
import os
import logging
from app_factory import create_app
from debug_config import setup_debug_logging, log_environment_info

# Setup debug logging first
setup_debug_logging()

# Configure detailed console logging for debugging
import sys

# Setup console logging
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_handler.setFormatter(console_formatter)

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[console_handler],
    format="%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
)

logger = logging.getLogger(__name__)

# Enable debug logging for key modules
logging.getLogger('app_factory').setLevel(logging.DEBUG)
logging.getLogger('blueprint_registry').setLevel(logging.DEBUG)
logging.getLogger('models').setLevel(logging.DEBUG)
logging.getLogger('routes').setLevel(logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.INFO)  # Reduce werkzeug noise
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)  # Reduce SQL noise

# Create the Flask app using the factory
try:
    app = create_app()
    logger.info("Flask application created successfully")
except Exception as e:
    logger.error("Failed to create Flask application: %s", str(e))
    raise

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    # Log environment and debug info
    log_environment_info()
    
    with app.app_context():
        logger.info("Starting Flask application on port %d", port)
        logger.info("Debug mode: %s", app.debug)
        logger.info("Config loaded: %s", app.config.get('ENVIRONMENT', 'default'))
        
        # Log registered blueprints
        logger.info("Registered blueprints: %s", [bp.name for bp in app.blueprints.values()])
        
        app.run(host='0.0.0.0', port=port, debug=True)