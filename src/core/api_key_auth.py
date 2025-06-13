from functools import wraps
from flask import request, jsonify
from src.models.api_key import APIKey
from src.extensions import db

def api_key_required(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'message': 'API key is required'}), 401
            
        key = APIKey.query.filter_by(key=api_key, is_active=True).first()
        
        if not key:
            return jsonify({'message': 'Invalid or deactivated API key'}), 401
            
        if key.is_expired():
            return jsonify({'message': 'API key has expired'}), 401
            
        return f(*args, **kwargs)
    
    return decorated
