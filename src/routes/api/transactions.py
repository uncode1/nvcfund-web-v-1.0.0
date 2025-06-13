from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.transaction import Transaction, TransactionStatus, TransactionType
from src.models.account import Account
from src.models.user import User
from src.extensions import db
from . import api

class TransactionResource(Resource):
    @jwt_required()
    def get(self, transaction_id):
        """Get transaction details."""
        current_user_id = get_jwt_identity()
        transaction = Transaction.query.filter_by(
            id=transaction_id,
            account_id=Account.query.filter_by(user_id=current_user_id).first().id
        ).first()
        if not transaction:
            return {'message': 'Transaction not found'}, 404
        return transaction.to_dict()

class TransactionListResource(Resource):
    @jwt_required()
    def get(self):
        """Get all transactions for the current user's accounts."""
        current_user_id = get_jwt_identity()
        transactions = Transaction.query.join(Account).filter(Account.user_id == current_user_id).all()
        return [transaction.to_dict() for transaction in transactions]

class TransactionCreateResource(Resource):
    @jwt_required()
    def post(self):
        """Create a new transaction."""
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Get the user's account
        account = Account.query.filter_by(
            id=data.get('account_id'),
            user_id=current_user_id
        ).first()
        
        if not account:
            return {'message': 'Account not found'}, 404
        
        # Generate a unique reference
        import random
        import string
        reference = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        
        transaction = Transaction(
            user_id=current_user_id,
            account_id=account.id,
            transaction_type=data.get('transaction_type'),
            amount=data.get('amount'),
            description=data.get('description'),
            reference=reference,
            status=TransactionStatus.PENDING
        )
        
        # Update account balance based on transaction type
        if transaction.transaction_type == TransactionType.DEPOSIT:
            account.balance += Decimal(str(transaction.amount))
        elif transaction.transaction_type == TransactionType.WITHDRAWAL:
            if account.balance < Decimal(str(transaction.amount)):
                transaction.status = TransactionStatus.FAILED
                transaction.description = "Insufficient funds"
            else:
                account.balance -= Decimal(str(transaction.amount))
        
        db.session.add(transaction)
        db.session.commit()
        return transaction.to_dict(), 201

# Register resources
api.add_resource(TransactionResource, '/transactions/<int:transaction_id>')
api.add_resource(TransactionListResource, '/transactions')
api.add_resource(TransactionCreateResource, '/transactions/create')
