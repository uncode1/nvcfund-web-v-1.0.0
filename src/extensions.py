from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from src.models.base import db

jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()
