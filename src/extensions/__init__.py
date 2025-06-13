from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail

# Initialize extensions
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()

def init_extensions(app):
    """Initialize all extensions with the Flask app."""
    db.init_app(app)
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    return db, jwt, login_manager, mail

__all__ = ['db', 'jwt', 'login_manager', 'mail', 'init_extensions']

db = SQLAlchemy()
