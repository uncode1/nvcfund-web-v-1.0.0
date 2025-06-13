"""Payment processing routes with secure validation."""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user

from ...models import (
    PaymentGateway, StablecoinAccount, Transaction, TransactionType,
    TransactionStatus
)
from ...services.payment_service import PaymentService
from ...utils.security_utils import sanitize_input, validate_amount


payments_bp = Blueprint('payments', __name__, url_prefix='/payments')


@payments_bp.route('/')
@login_required
def index():
    """Payment dashboard."""
    try:
        # Get user's recent payments
        recent_payments = PaymentService.get_user_transactions(
            user_id=current_user.id,
            limit=10,
            transaction_type=TransactionType.PAYMENT
        )
        
        # Get user's stablecoin accounts
        stablecoin_accounts = StablecoinAccount.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).all()
        
        return render_template('payments/index.html',
                             recent_payments=recent_payments,
                             stablecoin_accounts=stablecoin_accounts)
    except Exception as e:
        flash(f'Error loading payment dashboard: {str(e)}', 'error')
        return redirect(url_for('http.dashboard.index'))


@payments_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new_payment():
    """Create a new payment."""
    if request.method == 'POST':
        try:
            # Get form data
            payment_data = {
                'amount': request.form.get('amount'),
                'currency': sanitize_input(request.form.get('currency', 'USD')),
                'recipient_name': sanitize_input(request.form.get('recipient_name', '')),
                'recipient_account': sanitize_input(request.form.get('recipient_account', '')),
                'recipient_address': sanitize_input(request.form.get('recipient_address', '')),
                'description': sanitize_input(request.form.get('description', ''))
            }
            
            gateway_id = request.form.get('gateway_id')
            if gateway_id and gateway_id != '':
                gateway_id = int(gateway_id)
            else:
                gateway_id = None
            
            # Create payment
            success, message, transaction = PaymentService.create_payment(
                user_id=current_user.id,
                payment_data=payment_data,
                gateway_id=gateway_id
            )
            
            if success:
                flash(message, 'success')
                return redirect(url_for('http.payments.payment_detail', 
                                      transaction_id=transaction.transaction_id))
            else:
                flash(message, 'error')
                
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error creating payment: {str(e)}', 'error')
    
    # Get payment gateways for dropdown
    gateways = PaymentGateway.query.filter_by(is_active=True).all()
    
    return render_template('payments/new.html', gateways=gateways)


@payments_bp.route('/<transaction_id>')
@login_required
def payment_detail(transaction_id):
    """View payment details."""
    try:
        transaction = PaymentService.get_transaction_by_id(
            transaction_id=transaction_id,
            user_id=current_user.id
        )
        
        if not transaction:
            flash('Payment not found', 'error')
            return redirect(url_for('http.payments.index'))
        
        return render_template('payments/detail.html', transaction=transaction)
    except Exception as e:
        flash(f'Error loading payment details: {str(e)}', 'error')
        return redirect(url_for('http.payments.index'))


@payments_bp.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    """Transfer funds between stablecoin accounts."""
    if request.method == 'POST':
        try:
            to_account_number = sanitize_input(request.form.get('to_account_number', ''))
            amount = float(validate_amount(request.form.get('amount', 0)))
            description = sanitize_input(request.form.get('description', ''))
            
            success, message, transaction = PaymentService.process_stablecoin_transfer(
                from_user_id=current_user.id,
                to_account_number=to_account_number,
                amount=amount,
                description=description
            )
            
            if success:
                flash(message, 'success')
                return redirect(url_for('http.payments.payment_detail',
                                      transaction_id=transaction.transaction_id))
            else:
                flash(message, 'error')
                
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error processing transfer: {str(e)}', 'error')
    
    # Get user's stablecoin accounts
    user_accounts = StablecoinAccount.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).all()
    
    return render_template('payments/transfer.html', user_accounts=user_accounts)


@payments_bp.route('/history')
@login_required
def history():
    """View payment history."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Get transaction type filter
        transaction_type_filter = request.args.get('type')
        transaction_type = None
        
        if transaction_type_filter:
            try:
                transaction_type = TransactionType(transaction_type_filter.upper())
            except ValueError:
                pass
        
        # Get transactions with pagination
        transactions = PaymentService.get_user_transactions(
            user_id=current_user.id,
            limit=per_page,
            offset=(page - 1) * per_page,
            transaction_type=transaction_type
        )
        
        # Get total count for pagination (simplified)
        total_transactions = Transaction.query.filter_by(user_id=current_user.id).count()
        
        return render_template('payments/history.html',
                             transactions=transactions,
                             page=page,
                             per_page=per_page,
                             total=total_transactions,
                             transaction_type_filter=transaction_type_filter)
    except Exception as e:
        flash(f'Error loading payment history: {str(e)}', 'error')
        return redirect(url_for('http.payments.index'))


@payments_bp.route('/<transaction_id>/cancel', methods=['POST'])
@login_required
def cancel_payment(transaction_id):
    """Cancel a pending payment."""
    try:
        success, message = PaymentService.update_transaction_status(
            transaction_id=transaction_id,
            new_status=TransactionStatus.CANCELLED,
            user_id=current_user.id
        )
        
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
            
    except Exception as e:
        flash(f'Error cancelling payment: {str(e)}', 'error')
    
    return redirect(url_for('http.payments.payment_detail', transaction_id=transaction_id))


@payments_bp.route('/api/balance')
@login_required
def api_balance():
    """API endpoint to get user's stablecoin balance."""
    try:
        accounts = StablecoinAccount.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).all()
        
        balance_data = []
        for account in accounts:
            balance_data.append({
                'account_number': account.account_number,
                'balance': account.balance,
                'currency': account.currency,
                'account_type': account.account_type
            })
        
        return jsonify({
            'accounts': balance_data,
            'total_accounts': len(accounts)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@payments_bp.route('/api/validate-account', methods=['POST'])
@login_required
def api_validate_account():
    """API endpoint to validate recipient account."""
    try:
        data = request.get_json()
        account_number = sanitize_input(data.get('account_number', ''))
        
        if not account_number:
            return jsonify({'valid': False, 'message': 'Account number required'})
        
        # Check if account exists and is active
        account = StablecoinAccount.query.filter_by(
            account_number=account_number,
            is_active=True
        ).first()
        
        if account:
            # Don't return sensitive information
            return jsonify({
                'valid': True,
                'account_type': account.account_type,
                'currency': account.currency
            })
        else:
            return jsonify({
                'valid': False,
                'message': 'Account not found or inactive'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@payments_bp.route('/api/transaction/<transaction_id>/status')
@login_required
def api_transaction_status(transaction_id):
    """API endpoint to get transaction status."""
    try:
        transaction = PaymentService.get_transaction_by_id(
            transaction_id=transaction_id,
            user_id=current_user.id
        )
        
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        return jsonify({
            'transaction_id': transaction.transaction_id,
            'status': transaction.status.value,
            'amount': transaction.amount,
            'currency': transaction.currency,
            'created_at': transaction.created_at.isoformat(),
            'updated_at': transaction.updated_at.isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500