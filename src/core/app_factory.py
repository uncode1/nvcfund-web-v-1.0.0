#!/usr/bin/env python3
"""
Main application entry point
"""
import os
import logging
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from ..config import config
from ..routes import register_blueprints
from ..extensions import jwt, login_manager, mail, init_extensions
from ..models import db, init_models
from flask_moment import Moment
import logging
import os

# Initialize extensions (they will be initialized with app in create_app)
jwt = JWTManager()
login_manager = LoginManager()
moment = Moment()
from src.debug_config import setup_debug_logging, log_environment_info

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
def create_app(config_name=None):
    """Create and configure the Flask application."""
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')
    
    # Set the correct template and static directories
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'templates')
    static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'static')
    
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    # Update database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config.from_object(config[config_name])
    
    # Ensure database directory exists
    database_dir = os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', ''))
    os.makedirs(database_dir, exist_ok=True)
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    login_manager.init_app(app)
    moment.init_app(app)
    
    # Configure Flask-Login
    login_manager.login_view = 'http.auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        from ..models.user import User
        return User.query.get(int(user_id))
    
    # Initialize database
    with app.app_context():
        try:
            # Try to create tables
            db.create_all()
            
            # Check if users table exists and has the correct schema
            try:
                result = db.engine.execute("SELECT username FROM users LIMIT 1")
                result.fetchone()
            except Exception as e:
                # If username column is missing, recreate tables
                db.drop_all()
                db.create_all()
                
                # Log the recreation
                app.logger.warning('Database schema recreated due to missing columns')
                
        except Exception as e:
            app.logger.error(f'Database initialization failed: {str(e)}')
            raise
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register custom filters
    from ..filters import init_app
    init_app(app)
    
    # Set up logging
    setup_logging(app)
    
    return app

def register_error_handlers(app):
    """Register error handlers for the application."""
    from flask import render_template, jsonify, request
    
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found'}), 404
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        # Log the full error for debugging, but don't expose it to users
        app.logger.error(f'Server Error: {error}', exc_info=True)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Access forbidden'}), 403
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(400)
    def bad_request_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Bad request'}), 400
        return render_template('errors/400.html'), 400
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        # Log the full error for debugging
        app.logger.error(f'Unhandled Exception: {error}', exc_info=True)
        
        # Return a generic error response
        if request.path.startswith('/api/'):
            return jsonify({'error': 'An unexpected error occurred'}), 500
        return render_template('errors/500.html'), 500

def setup_logging(app):
    """Set up logging configuration."""
    if app.debug:
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
    
    # Add console handler
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
    ))
    app.logger.addHandler(handler)
    
    # Log environment info
    app.logger.info('Flask application created successfully')
    app.logger.info(f'Python Version: {sys.version}')
    app.logger.info(f'Working Directory: {os.getcwd()}')
    app.logger.info('Environment Variables:')
    for key in sorted(os.environ):
        if key.startswith('FLASK_'):
            app.logger.info(f'  {key}: {os.environ[key]}')
    
    # Log database initialization
    with app.app_context():
        app.logger.info('Database tables created successfully')

try:
    app = create_app()
    logger.info("Flask application created successfully")
except Exception as e:
    logger.error("Failed to create Flask application: %s", str(e))
    raise

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    # Log environment and debug info
    def log_environment_info():
        pass
    log_environment_info()
    
    with app.app_context():
        logger.info("Starting Flask application on port %d", port)
        logger.info("Debug mode: %s", app.debug)
        logger.info("Config loaded: %s", app.config.get('ENVIRONMENT', 'default'))
        
        # Log registered blueprints
        logger.info("Registered blueprints: %s", [bp.name for bp in app.blueprints.values()])
        
        app.run(host='0.0.0.0', port=port, debug=True)