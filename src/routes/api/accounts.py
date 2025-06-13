from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.account import Account
from src.models.user import User
from src.extensions import db
from . import api

class AccountResource(Resource):
    @jwt_required()
    def get(self, account_id):
        """Get account details."""
        current_user_id = get_jwt_identity()
        account = Account.query.filter_by(id=account_id, user_id=current_user_id).first()
        if not account:
            return {'message': 'Account not found'}, 404
        return account.to_dict()

class AccountListResource(Resource):
    @jwt_required()
    def get(self):
        """Get all accounts for the current user."""
        current_user_id = get_jwt_identity()
        accounts = Account.query.filter_by(user_id=current_user_id).all()
        return [account.to_dict() for account in accounts]

class AccountCreateResource(Resource):
    @jwt_required()
    def post(self):
        """Create a new account."""
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Generate a unique account number
        import random
        import string
        account_number = ''.join(random.choices(string.digits, k=10))
        
        account = Account(
            user_id=current_user_id,
            account_number=account_number,
            account_type=data.get('account_type'),
            balance=data.get('initial_balance', 0.0)  # Allow initial balance
        )
        
        db.session.add(account)
        db.session.commit()
        return account.to_dict(), 201

# Register resources
api.add_resource(AccountResource, '/accounts/<int:account_id>')
api.add_resource(AccountListResource, '/accounts')
api.add_resource(AccountCreateResource, '/accounts/create')
