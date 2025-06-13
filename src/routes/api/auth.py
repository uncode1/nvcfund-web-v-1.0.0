from flask_restful import Resource
from flask import request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from src.models.user import User
from src.extensions import db

from . import api

@api.resource('/auth/login')
class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            access_token = create_access_token(identity=user.id)
            return {
                'access_token': access_token,
                'user': user.to_dict()
            }
        return {'error': 'Invalid credentials'}, 401

@api.resource('/auth/register')
class RegisterResource(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        
        if User.query.filter_by(email=email).first():
            return {'error': 'Email already registered'}, 400
            
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        return user.to_dict(), 201

@api.resource('/auth/me')
class MeResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return {'error': 'User not found'}, 404
        return user.to_dict()
