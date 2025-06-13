from flask import Blueprint

http_bp = Blueprint('http', __name__, url_prefix='')

# Import and register sub-blueprints
from .auth import auth_bp
from .dashboard import dashboard_bp
from .transactions import transactions_bp
from .treasury import treasury_bp
from .payments import payments_bp

# Register sub-blueprints with the main http blueprint
http_bp.register_blueprint(auth_bp)
http_bp.register_blueprint(dashboard_bp)
http_bp.register_blueprint(transactions_bp)
http_bp.register_blueprint(treasury_bp)
http_bp.register_blueprint(payments_bp)
