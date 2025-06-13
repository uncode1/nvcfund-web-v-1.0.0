#!/usr/bin/env python3
"""
Main application entry point
"""
import os
import logging
from src.core.app_factory import create_app

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Enable debug logging for key modules
logging.getLogger('app_factory').setLevel(logging.DEBUG)
logging.getLogger('blueprint_registry').setLevel(logging.DEBUG)
logging.getLogger('models').setLevel(logging.DEBUG)
logging.getLogger('routes').setLevel(logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.INFO)
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

if __name__ == '__main__':
    try:
        app = create_app()
        logger.info("Flask application created successfully")
        
        # Start the application
        port = int(os.environ.get('PORT', 5000))
        logger.info("Starting Flask application on port %d", port)
        
        with app.app_context():
            # Log environment info
            logger.info("Debug mode: %s", app.debug)
            logger.info("Config loaded: %s", app.config.get('ENVIRONMENT', 'default'))
            
            # Log registered blueprints
            logger.info("Registered blueprints: %s", [bp.name for bp in app.blueprints.values()])
            
            # Run the application
            app.run(debug=True)
    except Exception as e:
        logger.error("Failed to start Flask application: %s", str(e))