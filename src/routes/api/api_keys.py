from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.api_key import APIKey
from src.models.user import User
from src.extensions import db
from . import api

class APIKeyListResource(Resource):
    @jwt_required()
    def get(self):
        """Get all API keys for the current user."""
        current_user_id = get_jwt_identity()
        api_keys = APIKey.query.filter_by(
            user_id=current_user_id,
            is_active=True
        ).all()
        return [key.to_dict() for key in api_keys]

    @jwt_required()
    def post(self):
        """Create a new API key."""
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        description = data.get('description')
        expires_in_days = data.get('expires_in_days')
        
        api_key = APIKey(
            user_id=current_user_id,
            description=description,
            expires_in_days=expires_in_days
        )
        
        db.session.add(api_key)
        db.session.commit()
        
        return api_key.to_dict(), 201

class APIKeyResource(Resource):
    @jwt_required()
    def get(self, key_id):
        """Get a specific API key."""
        current_user_id = get_jwt_identity()
        api_key = APIKey.query.filter_by(
            id=key_id,
            user_id=current_user_id,
            is_active=True
        ).first()
        
        if not api_key:
            return {'message': 'API key not found'}, 404
        
        return api_key.to_dict()

    @jwt_required()
    def delete(self, key_id):
        """Delete an API key."""
        current_user_id = get_jwt_identity()
        api_key = APIKey.query.filter_by(
            id=key_id,
            user_id=current_user_id,
            is_active=True
        ).first()
        
        if not api_key:
            return {'message': 'API key not found'}, 404
        
        api_key.is_active = False
        db.session.commit()
        
        return {'message': 'API key deactivated successfully'}

# Register resources
api.add_resource(APIKeyListResource, '/api-keys')
api.add_resource(APIKeyResource, '/api-keys/<string:key_id>')
