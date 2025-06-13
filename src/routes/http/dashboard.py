from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from src.models.user import User
from src.models.account import Account
from src.models.transaction import Transaction
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    """Dashboard overview page."""
    # Get user's accounts
    accounts = Account.query.filter_by(user_id=current_user.id).all()
    
    # Get recent transactions
    recent_transactions = Transaction.query.filter_by(user_id=current_user.id)\
        .order_by(Transaction.created_at.desc())\
        .limit(10).all()
    
    # Calculate total balance
    total_balance = sum(account.balance for account in accounts)
    
    return render_template('dashboard.html',
                         accounts=accounts,
                         recent_transactions=recent_transactions,
                         total_balance=total_balance)

@dashboard_bp.route('/transactions')
@login_required
def transactions():
    """Transaction history page."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    transactions = Transaction.query.filter_by(user_id=current_user.id)\
        .order_by(Transaction.created_at.desc())\
        .paginate(page=page, per_page=per_page)
    
    return render_template('dashboard/transactions.html',
                         transactions=transactions,
                         page=page,
                         per_page=per_page)
