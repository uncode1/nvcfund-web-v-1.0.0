def register_blueprints(app):
    """Register all Flask blueprints."""
    from .api import api_bp
    from .http import http_bp
    
    app.register_blueprint(api_bp)
    app.register_blueprint(http_bp)
