"""Treasury management routes with secure access controls."""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from datetime import datetime

from ...models import (
    TreasuryAccount, TreasuryInvestment, TreasuryAccountType,
    InvestmentType, FinancialInstitution
)
from ...services.treasury_service import TreasuryService
from ...utils.security_utils import admin_required, sanitize_input


treasury_bp = Blueprint('treasury', __name__, url_prefix='/treasury')


@treasury_bp.route('/')
@login_required
@admin_required
def dashboard():
    """Treasury management dashboard."""
    try:
        # Get portfolio overview
        portfolio = TreasuryService.get_portfolio_overview()
        
        # Get recent accounts
        recent_accounts = TreasuryAccount.query.filter_by(is_active=True)\
            .order_by(TreasuryAccount.created_at.desc())\
            .limit(5).all()
        
        return render_template('treasury/dashboard.html',
                             portfolio=portfolio,
                             recent_accounts=recent_accounts)
    except Exception as e:
        flash(f'Error loading treasury dashboard: {str(e)}', 'error')
        return redirect(url_for('http.dashboard.index'))


@treasury_bp.route('/accounts')
@login_required
@admin_required
def accounts():
    """List all treasury accounts."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        accounts = TreasuryAccount.query.filter_by(is_active=True)\
            .order_by(TreasuryAccount.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template('treasury/accounts.html',
                             accounts=accounts)
    except Exception as e:
        flash(f'Error loading accounts: {str(e)}', 'error')
        return redirect(url_for('http.treasury.dashboard'))


@treasury_bp.route('/accounts/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_account():
    """Create a new treasury account."""
    if request.method == 'POST':
        try:
            # Get form data
            name = sanitize_input(request.form.get('name', ''))
            account_type_str = request.form.get('account_type', '')
            institution_id = request.form.get('institution_id')
            initial_balance = float(request.form.get('initial_balance', 0))
            currency = sanitize_input(request.form.get('currency', 'USD'))
            description = sanitize_input(request.form.get('description', ''))
            
            # Validate account type
            try:
                account_type = TreasuryAccountType(account_type_str)
            except ValueError:
                flash('Invalid account type selected', 'error')
                return redirect(url_for('http.treasury.new_account'))
            
            # Convert institution_id to int if provided
            if institution_id and institution_id != '':
                institution_id = int(institution_id)
            else:
                institution_id = None
            
            # Create account
            success, message, account = TreasuryService.create_treasury_account(
                name=name,
                account_type=account_type,
                institution_id=institution_id,
                initial_balance=initial_balance,
                currency=currency,
                description=description
            )
            
            if success:
                flash(message, 'success')
                return redirect(url_for('http.treasury.account_detail', account_id=account.id))
            else:
                flash(message, 'error')
                
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error creating account: {str(e)}', 'error')
    
    # Get institutions for dropdown
    institutions = FinancialInstitution.query.filter_by(is_active=True).all()
    account_types = list(TreasuryAccountType)
    
    return render_template('treasury/new_account.html',
                         institutions=institutions,
                         account_types=account_types)


@treasury_bp.route('/accounts/<int:account_id>')
@login_required
@admin_required
def account_detail(account_id):
    """View treasury account details."""
    try:
        account_summary = TreasuryService.get_account_summary(account_id)
        
        if not account_summary:
            flash('Account not found', 'error')
            return redirect(url_for('http.treasury.accounts'))
        
        return render_template('treasury/account_detail.html',
                             account_summary=account_summary)
    except Exception as e:
        flash(f'Error loading account details: {str(e)}', 'error')
        return redirect(url_for('http.treasury.accounts'))


@treasury_bp.route('/transfer', methods=['GET', 'POST'])
@login_required
@admin_required
def transfer():
    """Transfer funds between treasury accounts."""
    if request.method == 'POST':
        try:
            from_account_id = int(request.form.get('from_account_id'))
            to_account_id = int(request.form.get('to_account_id'))
            amount = float(request.form.get('amount'))
            description = sanitize_input(request.form.get('description', ''))
            
            success, message, transaction = TreasuryService.transfer_funds(
                from_account_id=from_account_id,
                to_account_id=to_account_id,
                amount=amount,
                description=description,
                user_id=current_user.id
            )
            
            if success:
                flash(message, 'success')
                return redirect(url_for('http.treasury.dashboard'))
            else:
                flash(message, 'error')
                
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error processing transfer: {str(e)}', 'error')
    
    # Get active accounts for dropdowns
    accounts = TreasuryAccount.query.filter_by(is_active=True).all()
    
    return render_template('treasury/transfer.html', accounts=accounts)


@treasury_bp.route('/investments')
@login_required
@admin_required
def investments():
    """List treasury investments."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        investments = TreasuryInvestment.query\
            .order_by(TreasuryInvestment.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template('treasury/investments.html',
                             investments=investments)
    except Exception as e:
        flash(f'Error loading investments: {str(e)}', 'error')
        return redirect(url_for('http.treasury.dashboard'))


@treasury_bp.route('/investments/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_investment():
    """Create a new treasury investment."""
    if request.method == 'POST':
        try:
            account_id = int(request.form.get('account_id'))
            investment_type_str = request.form.get('investment_type')
            amount = float(request.form.get('amount'))
            interest_rate = float(request.form.get('interest_rate'))
            start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
            maturity_date = datetime.strptime(request.form.get('maturity_date'), '%Y-%m-%d')
            institution_id = request.form.get('institution_id')
            description = sanitize_input(request.form.get('description', ''))
            
            # Validate investment type
            try:
                investment_type = InvestmentType(investment_type_str)
            except ValueError:
                flash('Invalid investment type selected', 'error')
                return redirect(url_for('http.treasury.new_investment'))
            
            # Convert institution_id to int if provided
            if institution_id and institution_id != '':
                institution_id = int(institution_id)
            else:
                institution_id = None
            
            success, message, investment = TreasuryService.create_investment(
                account_id=account_id,
                investment_type=investment_type,
                amount=amount,
                interest_rate=interest_rate,
                start_date=start_date,
                maturity_date=maturity_date,
                institution_id=institution_id,
                description=description
            )
            
            if success:
                flash(message, 'success')
                return redirect(url_for('http.treasury.investments'))
            else:
                flash(message, 'error')
                
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error creating investment: {str(e)}', 'error')
    
    # Get data for dropdowns
    accounts = TreasuryAccount.query.filter_by(is_active=True).all()
    institutions = FinancialInstitution.query.filter_by(is_active=True).all()
    investment_types = list(InvestmentType)
    
    return render_template('treasury/new_investment.html',
                         accounts=accounts,
                         institutions=institutions,
                         investment_types=investment_types)


@treasury_bp.route('/api/portfolio')
@login_required
@admin_required
def api_portfolio():
    """API endpoint for portfolio data."""
    try:
        portfolio = TreasuryService.get_portfolio_overview()
        return jsonify(portfolio)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@treasury_bp.route('/api/accounts/<int:account_id>/summary')
@login_required
@admin_required
def api_account_summary(account_id):
    """API endpoint for account summary."""
    try:
        summary = TreasuryService.get_account_summary(account_id)
        if summary:
            return jsonify(summary)
        else:
            return jsonify({'error': 'Account not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500