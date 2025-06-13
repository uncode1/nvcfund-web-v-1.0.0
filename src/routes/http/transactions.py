from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from src.models.transaction import Transaction
from src.models.account import Account
from datetime import datetime

transactions_bp = Blueprint('http_transactions', __name__)

@transactions_bp.route('/transactions/<int:transaction_id>')
@login_required
def view_transaction(transaction_id):
    """View a specific transaction."""
    transaction = Transaction.query.filter_by(
        id=transaction_id,
        user_id=current_user.id
    ).first_or_404()
    
    return render_template('transactions/view.html', transaction=transaction)

@transactions_bp.route('/transactions/new')
@login_required
def new_transaction():
    """Create a new transaction page."""
    accounts = Account.query.filter_by(user_id=current_user.id).all()
    return render_template('transactions/new.html', accounts=accounts)

@transactions_bp.route('/transactions/create', methods=['POST'])
@login_required
def create_transaction():
    """Create a new transaction."""
    account_id = request.form.get('account_id')
    amount = request.form.get('amount')
    type = request.form.get('type')
    description = request.form.get('description')
    
    # Get the user's account
    account = Account.query.filter_by(
        id=account_id,
        user_id=current_user.id
    ).first()
    
    if not account:
        flash('Account not found', 'error')
        return redirect(url_for('http_transactions.new_transaction'))
    
    # Create transaction
    transaction = Transaction(
        user_id=current_user.id,
        account_id=account.id,
        amount=amount,
        type=type,
        description=description
    )
    
    # Update account balance
    if type == 'debit':
        account.update_balance(-amount)
    else:
        account.update_balance(amount)
    
    # Save to database
    db.session.add(transaction)
    db.session.commit()
    
    flash('Transaction created successfully', 'success')
    return redirect(url_for('dashboard.index'))
